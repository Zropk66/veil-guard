#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"
#include "image_map.hpp"
#include "decode.hpp"
#include "memory.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::platform {

// 代码重映射。
//
// 把一段代码从原映像复制到私有可执行页，原地修正 RIP 相对寻址与
// 基址重定位项，并把原 .pdata 展开信息登记到新页。
//
// 目的不是隐藏，而是让「在原地址下断点」与「在原地址上打补丁」失效：
// 执行流走的是新页，原页上的修改不影响实际执行的指令。攻击者要
// 定位新页，必须先发现重映射本身。
//
// 边界：重映射只覆盖重定位表能描述的引用。通过寄存器间接调用、
// 或经数据段指针跳转的路径仍指向原映像，因此被重映射的代码不能
// 依赖那些路径访问自身。这一约束由调用方保证，库不试图自动修复。
class RemappedCode {
public:
    RemappedCode() noexcept = default;
    ~RemappedCode() noexcept { release(); }

    RemappedCode(const RemappedCode&) = delete;
    RemappedCode& operator=(const RemappedCode&) = delete;

    // 把 module 中 [begin, begin + size) 的字节复制到私有可执行页。
    //
    // begin 必须是模块内的虚拟地址。size 向上取整到页，尾部字节保持
    // 为零，避免把相邻函数带进新页。
    bool map(const void* module, const void* begin, std::size_t size) noexcept {
        release();

        if (module == nullptr || begin == nullptr || size == 0)
            return false;

        ImageLayout layout{};
        if (!describe_image(module, &layout))
            return false;

        const auto base = reinterpret_cast<std::uintptr_t>(layout.base);
        const auto target = reinterpret_cast<std::uintptr_t>(begin);
        if (target < base || target + size > base + layout.size_of_image)
            return false;

        const std::size_t page_size = page_span(size);
        if (page_size == 0)
            return false;

        // RIP 相对寻址的位移字段只有 32 位，新页与原页的距离必须
        // 落在该范围内，否则无法修正。VirtualAlloc 默认在堆区分配，
        // 与映像区相距数 TB，必然超出范围。因此请求分配点落在原页
        // 附近，并在失败时逐级放宽，直到地址差可编码为止。
        auto* mapped = allocate_near(begin, page_size, 0);
        if (mapped == nullptr)
            return false;

        mapped_ = mapped;
        mapped_size_ = page_size;
        source_ = static_cast<const std::uint8_t*>(begin);
        region_size_ = size;
        delta_ = reinterpret_cast<std::intptr_t>(mapped) -
                 reinterpret_cast<std::intptr_t>(begin);

        // 复制原始字节。未覆盖的尾部保持为零。
        for (std::size_t i = 0; i < size; ++i)
            mapped_[i] = source_[i];

        if (!apply_relocations(layout))
            return false;

        if (!apply_rip_references())
            return false;

        if (!protect_executable())
            return false;

        if (!register_unwind(layout))
            return false;

        FlushInstructionCache(GetCurrentProcess(), mapped_, page_size);
        ready_ = true;
        return true;
    }

    bool ready() const noexcept { return ready_; }
    void* entry() const noexcept { return mapped_; }
    std::size_t size() const noexcept { return mapped_size_; }

    // 相对原地址的位移。调用方据此把指向原代码的指针换算到新页。
    std::intptr_t delta() const noexcept { return delta_; }

    // 查询某地址所在函数的边界。返回 false 表示该地址不在任何已
    // 登记的函数内，此时无法确定映射范围，调用方应放弃重映射。
    static bool function_bounds(const void* module, const void* address,
                                const void** begin, std::size_t* size) noexcept {
        ImageLayout layout{};
        if (!describe_image(module, &layout))
            return false;
        if (layout.exception_table.VirtualAddress == 0)
            return false;

        const auto* table = reinterpret_cast<const RUNTIME_FUNCTION*>(
            layout.base + layout.exception_table.VirtualAddress);
        const std::size_t count =
            layout.exception_table.Size / sizeof(RUNTIME_FUNCTION);

        const auto target = reinterpret_cast<std::uintptr_t>(address);
        const auto base = reinterpret_cast<std::uintptr_t>(layout.base);

        for (std::size_t i = 0; i < count; ++i) {
            const auto function_begin = base + table[i].BeginAddress;
            const auto function_end = base + table[i].EndAddress;
            if (target < function_begin || target >= function_end)
                continue;

            if (begin != nullptr)
                *begin = reinterpret_cast<const void*>(function_begin);
            if (size != nullptr)
                *size = function_end - function_begin;
            return true;
        }
        return false;
    }

    // 按函数边界映射。地址必须落在已登记的函数内。
    bool map_function(const void* module, const void* address) noexcept {
        const void* begin = nullptr;
        std::size_t size = 0;
        if (!function_bounds(module, address, &begin, &size))
            return false;
        return map(module, begin, size);
    }

    void release() noexcept {
        if (unwind_ != nullptr) {
            RtlDeleteFunctionTable(unwind_);
            VirtualFree(unwind_, 0, MEM_RELEASE);
            unwind_ = nullptr;
        }
        unwind_count_ = 0;

        if (mapped_ != nullptr) {
            VirtualFree(mapped_, 0, MEM_RELEASE);
            mapped_ = nullptr;
        }
        mapped_size_ = 0;
        region_size_ = 0;
        source_ = nullptr;
        delta_ = 0;
        ready_ = false;
    }

private:
    static std::size_t page_span(std::size_t size) noexcept {
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        const std::size_t page = info.dwPageSize != 0 ? info.dwPageSize : 4096;
        if (size > (1u << 24))
            return 0;
        return ((size + page - 1) / page) * page;
    }

    // 在原页附近分配，使地址差落在 32 位位移可编码的范围内。
    //
    // 从原页所在的分配粒度边界开始，按 64KB 步长向两侧探测。
    // 步长取分配粒度而非页大小，避免在同一 64KB 区域内反复失败。
    static std::uint8_t* allocate_near(const void* near_address,
                                       std::size_t size,
                                       std::size_t attempt) noexcept {
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        const std::uintptr_t granularity =
            info.dwAllocationGranularity != 0 ? info.dwAllocationGranularity
                                              : 0x10000;
        const std::uintptr_t lowest =
            reinterpret_cast<std::uintptr_t>(info.lpMinimumApplicationAddress);
        const std::uintptr_t highest =
            reinterpret_cast<std::uintptr_t>(info.lpMaximumApplicationAddress);
        const std::uintptr_t origin =
            reinterpret_cast<std::uintptr_t>(near_address);

        constexpr std::size_t MAX_ATTEMPTS = 2048;

        for (std::size_t i = attempt; i < MAX_ATTEMPTS; ++i) {
            const std::uintptr_t step = granularity * (i + 1);

            const std::uintptr_t forward = (origin + step) & ~(granularity - 1);
            if (forward > lowest && forward + size < highest) {
                void* page = VirtualAlloc(reinterpret_cast<void*>(forward), size,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
                if (page != nullptr)
                    return static_cast<std::uint8_t*>(page);
            }

            if (origin > lowest + step) {
                const std::uintptr_t backward =
                    (origin - step) & ~(granularity - 1);
                if (backward > lowest && backward + size < highest) {
                    void* page = VirtualAlloc(reinterpret_cast<void*>(backward),
                                              size, MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
                    if (page != nullptr)
                        return static_cast<std::uint8_t*>(page);
                }
            }
        }
        return nullptr;
    }

    // 只修正落在被映射区间内的重定位项。
    //
    // 落在区间外的项指向的是原映像的其他部分，那些部分仍在原地址
    // 上执行，修正它们反而会破坏原映像。区间内的 DIR64 项按新地址
    // 与旧地址之差修正；HIGHLOW 项按 32 位截断修正，超出范围的
    // 情形视为不可重映射。
    bool apply_relocations(const ImageLayout& layout) noexcept {
        RelocationWalker walker;
        if (!walker.init(layout))
            return true;  // 无重定位表说明映像已按固定基址链接

        walker.bind_base(layout);

        const auto region_begin = reinterpret_cast<std::uintptr_t>(source_);
        const auto region_end = region_begin + region_size_;
        const auto mapped_begin = reinterpret_cast<std::uintptr_t>(mapped_);

        void* target = nullptr;
        std::uint32_t type = 0;
        while (walker.next(&target, &type)) {
            if (type == IMAGE_REL_BASED_ABSOLUTE || target == nullptr)
                continue;

            const auto address = reinterpret_cast<std::uintptr_t>(target);
            if (address < region_begin || address >= region_end)
                continue;

            const std::size_t offset = address - region_begin;
            auto* slot = reinterpret_cast<std::uint8_t*>(mapped_begin + offset);

            if (type == IMAGE_REL_BASED_DIR64) {
                std::uint64_t value = 0;
                for (std::size_t i = 0; i < 8; ++i)
                    value |= static_cast<std::uint64_t>(slot[i]) << (i * 8);

                value += static_cast<std::uint64_t>(delta_);

                for (std::size_t i = 0; i < 8; ++i)
                    slot[i] = static_cast<std::uint8_t>(value >> (i * 8));
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                std::uint32_t value = 0;
                for (std::size_t i = 0; i < 4; ++i)
                    value |= static_cast<std::uint32_t>(slot[i]) << (i * 8);

                const std::int64_t adjusted =
                    static_cast<std::int64_t>(value) + delta_;
                if (adjusted < 0 || adjusted > 0xFFFFFFFFLL)
                    return false;

                value = static_cast<std::uint32_t>(adjusted);

                for (std::size_t i = 0; i < 4; ++i)
                    slot[i] = static_cast<std::uint8_t>(value >> (i * 8));
            }
        }
        return true;
    }

    // 修正 RIP 相对寻址。
    //
    // 重定位表覆盖不到同映像内部的引用，但复制到新页后这些指令的
    // RIP 基准变了，位移字节却仍是原值，目标会整体偏移 delta。
    // 这里逐条解码，把位移重算为「原目标 - 新指令末尾地址」。
    //
    // 目标是区间内的地址时，换算后指向新页内的对应位置；目标是
    // 区间外的原映像地址时，换算后仍指向原映像，这是期望行为。
    //
    // 解码到未知编码即停止修正并返回失败。停止后剩余字节里的 RIP
    // 引用保持错误状态，继续执行会崩溃，因此宁可整体拒绝映射。
    bool apply_rip_references() noexcept {
        const auto mapped_begin = reinterpret_cast<std::uintptr_t>(mapped_);
        const auto source_begin = reinterpret_cast<std::uintptr_t>(source_);

        bool clean = true;
        const std::size_t scanned = InstructionScanner::scan(
            mapped_, region_size_, [&](const InstructionScanner::RipReference& ref) {
                const std::int64_t original_target =
                    static_cast<std::int64_t>(source_begin) + ref.target_offset;

                const auto instruction_end =
                    static_cast<std::int64_t>(mapped_begin) +
                    static_cast<std::int64_t>(ref.disp_offset) + 4;

                const std::int64_t adjusted = original_target - instruction_end;
                if (adjusted < -0x80000000LL || adjusted > 0x7FFFFFFFLL) {
                    clean = false;
                    return;
                }

                const auto value = static_cast<std::int32_t>(adjusted);
                for (std::size_t i = 0; i < 4; ++i)
                    mapped_[ref.disp_offset + i] =
                        static_cast<std::uint8_t>(value >> (i * 8));
            });

        // 解码未覆盖整个请求区间说明遇到了未知编码
        return clean && scanned == region_size_;
    }

    bool protect_executable() noexcept {
        DWORD previous = 0;
        if (!VirtualProtect(mapped_, mapped_size_, PAGE_EXECUTE_READ,
                            &previous))
            return false;
        return true;
    }

    // 把原映像中覆盖被映射区间的展开信息登记到新页。
    //
    // 没有这一步，新页上抛出的异常会让展开器找不到函数边界，
    // 异常被静默吞掉或直接终止进程。登记用 RtlAddFunctionTable，
    // 它以模块基址加相对地址描述，因此只需把表项里的 BeginAddress
    // 与 UnwindData 按位移修正后整块提交。
    bool register_unwind(const ImageLayout& layout) noexcept {
        if (layout.exception_table.VirtualAddress == 0 ||
            layout.exception_table.Size < sizeof(RUNTIME_FUNCTION))
            return true;  // 无展开信息说明该映像不使用 SEH

        const auto* table = reinterpret_cast<const RUNTIME_FUNCTION*>(
            layout.base + layout.exception_table.VirtualAddress);
        const std::size_t count =
            layout.exception_table.Size / sizeof(RUNTIME_FUNCTION);

        const auto region_begin = reinterpret_cast<std::uintptr_t>(source_);
        const auto region_end = region_begin + region_size_;

        // 先统计落在区间内的表项，避免二次遍历时越界
        std::size_t inside = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto begin = reinterpret_cast<std::uintptr_t>(layout.base) +
                               table[i].BeginAddress;
            const auto end = reinterpret_cast<std::uintptr_t>(layout.base) +
                             table[i].EndAddress;
            if (begin >= region_begin && end <= region_end)
                ++inside;
        }

        if (inside == 0)
            return true;

        auto* entries = static_cast<RUNTIME_FUNCTION*>(
            VirtualAlloc(nullptr, inside * sizeof(RUNTIME_FUNCTION),
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (entries == nullptr)
            return false;

        std::size_t cursor = 0;
        for (std::size_t i = 0; i < count && cursor < inside; ++i) {
            const auto begin = reinterpret_cast<std::uintptr_t>(layout.base) +
                               table[i].BeginAddress;
            const auto end = reinterpret_cast<std::uintptr_t>(layout.base) +
                             table[i].EndAddress;
            if (begin < region_begin || end > region_end)
                continue;

            entries[cursor] = table[i];
            entries[cursor].BeginAddress =
                static_cast<DWORD>(begin - region_begin);
            entries[cursor].EndAddress =
                static_cast<DWORD>(end - region_begin);
            ++cursor;
        }

        // UnwindData 指向 .pdata 之外时按位移修正；指向映像内部时
        // 该地址仍是有效的原映像地址，无需修正。两种情形都以
        // 「是否落在被映射区间」为判据。
        for (std::size_t i = 0; i < cursor; ++i) {
            const auto unwind = reinterpret_cast<std::uintptr_t>(layout.base) +
                                (entries[i].UnwindData);
            if (unwind >= region_begin && unwind < region_end)
                entries[i].UnwindData = static_cast<DWORD>(
                    unwind - region_begin);
        }

        if (!RtlAddFunctionTable(entries, static_cast<DWORD>(cursor),
                                 reinterpret_cast<DWORD64>(mapped_))) {
            VirtualFree(entries, 0, MEM_RELEASE);
            return false;
        }

        unwind_ = entries;
        unwind_count_ = cursor;
        return true;
    }

    std::uint8_t* mapped_ = nullptr;
    std::size_t mapped_size_ = 0;
    const std::uint8_t* source_ = nullptr;
    std::size_t region_size_ = 0;
    std::intptr_t delta_ = 0;
    bool ready_ = false;
    RUNTIME_FUNCTION* unwind_ = nullptr;
    std::size_t unwind_count_ = 0;
};

}  // namespace veil::platform
