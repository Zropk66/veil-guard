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

        // 展开信息副本写在代码之后的页内空间，必须在整页改为只读可执行
        // 之前完成。顺序颠倒会让那次写入触发访问违规。
        if (!register_unwind(layout))
            return false;

        if (!protect_executable())
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

    // 查询某地址所在函数的边界。
    //
    // 返回的区间必须自包含控制流出口。.pdata 的 EndAddress 不满足这一点：
    // 编译器会把尾部的 ret 合并到下一个函数，此时前一个函数的条目结束于
    // ret 之前。按该长度复制出的副本执行到末尾会冲进零填充，随即崩溃。
    // 因此无论边界来自 .pdata 还是解码推导，都要向后延伸到返回指令。
    //
    // .pdata 只登记需要展开信息的函数，不抛异常、不调栈检查的叶子函数
    // 没有条目。这类函数在表里查不到，但同样可以重映射，此时边界完全
    // 由解码推导。
    static bool function_bounds(const void* module, const void* address,
                                const void** begin, std::size_t* size) noexcept {
        ImageLayout layout{};
        if (!describe_image(module, &layout))
            return false;

        const auto target = reinterpret_cast<std::uintptr_t>(address);
        const auto base = reinterpret_cast<std::uintptr_t>(layout.base);
        const auto image_end = base + layout.size_of_image;

        if (layout.base == nullptr || target < base || target >= image_end)
            return false;
        if (!is_executable_address(layout, target))
            return false;

        // 已知的函数分界，同时充当扫描的硬上限
        std::uintptr_t start = target;
        std::uintptr_t limit = image_end;

        if (layout.exception_table.VirtualAddress != 0) {
            const auto* table = reinterpret_cast<const RUNTIME_FUNCTION*>(
                layout.base + layout.exception_table.VirtualAddress);
            const std::size_t count =
                layout.exception_table.Size / sizeof(RUNTIME_FUNCTION);

            bool inside_entry = false;
            for (std::size_t i = 0; i < count; ++i) {
                const auto ent_begin = base + table[i].BeginAddress;
                const auto ent_end = base + table[i].EndAddress;

                if (target >= ent_begin && target < ent_end) {
                    start = ent_begin;
                    limit = ent_end;
                    inside_entry = true;
                    break;
                }
                if (ent_begin > target && ent_begin < limit)
                    limit = ent_begin;
            }

            // 条目命中时，尾合并的 ret 在条目之外，放宽到下一个条目起点。
            // 下一个起点可能恰好等于 ent_end，因此用 >= 而不是 >。
            if (inside_entry) {
                std::uintptr_t next = image_end;
                for (std::size_t i = 0; i < count; ++i) {
                    const auto ent_begin = base + table[i].BeginAddress;
                    if (ent_begin >= limit && ent_begin < next)
                        next = ent_begin;
                }
                limit = next;
            }
        }

        const std::size_t size_at = scan_to_exit(
            reinterpret_cast<const std::uint8_t*>(start), target - start,
            limit - start);
        if (size_at == 0)
            return false;

        if (begin != nullptr)
            *begin = reinterpret_cast<const void*>(start);
        if (size != nullptr)
            *size = size_at;
        return true;
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
    // 地址是否落在某个带 IMAGE_SCN_MEM_EXECUTE 的段内
    static bool is_executable_address(const ImageLayout& layout,
                                      std::uintptr_t address) noexcept {
        const auto* section = section_table(layout.base);
        if (section == nullptr)
            return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            layout.base + reinterpret_cast<const IMAGE_DOS_HEADER*>(
                               layout.base)->e_lfanew);
        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(layout.base);

        for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                continue;
            const auto begin = base + section[i].VirtualAddress;
            const auto end = begin + section[i].Misc.VirtualSize;
            if (address >= begin && address < end)
                return true;
        }
        return false;
    }

    // 从 start 逐条解码，返回需要复制的字节数。
    //
    // 不能停在第一条 ret。尾合并会让一个函数的短跳转越过自己的 ret
    // 落到相邻代码块，那里才是真正的出口。只复制到 ret 会让副本里的
    // 跳转落到零填充上，随即崩溃。
    //
    // 因此扫完整个 limit 区间，记录最后一条返回指令的位置与所有分支
    // 目标的最大值，取两者较大者作为终点。minimum 是必须覆盖的字节数，
    // 取目标地址相对起点的偏移加一。limit 取下一个已知函数的起点。
    static std::size_t scan_to_exit(const std::uint8_t* start,
                                    std::size_t minimum,
                                    std::size_t limit) noexcept {
        if (start == nullptr || limit < minimum + 1)
            return 0;

        std::size_t scanned = 0;
        std::size_t last_exit = 0;
        std::size_t max_branch = 0;

        while (scanned < limit) {
            const std::uint8_t opcode = start[scanned];

            if (opcode == 0xC3 || opcode == 0xCB) {
                ++scanned;
                last_exit = scanned;
                continue;
            }
            // int3 填充：函数已结束，后续字节不属于本函数
            if (opcode == 0xCC)
                break;

            const std::size_t length = InstructionScanner::instruction_length(
                start + scanned, limit - scanned);
            if (length == 0)
                break;

            std::size_t branch_to = 0;
            if (InstructionScanner::branch_target(start + scanned, length,
                                                  &branch_to)) {
                // branch_target 给出的是相对该指令起点的偏移
                const std::size_t absolute = scanned + branch_to;
                if (absolute <= limit && absolute > max_branch)
                    max_branch = absolute;
            }

            scanned += length;
        }

        std::size_t end = last_exit > max_branch ? last_exit : max_branch;
        if (end < scanned && last_exit == 0)
            end = scanned;

        if (end < minimum + 1 || end > limit)
            return 0;

        return end;
    }

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
    // RtlAddFunctionTable 的 BaseAddress 是新页，表项里的 BeginAddress、
    // EndAddress 与 UnwindData 全部被解释为相对该基址的偏移。原映像的
    // .xdata 留在原处，若把它的原 RVA 直接填进去，展开器会到新页的
    // 对应偏移处读到零填充，解析出无效的展开码后崩溃——即便被调用的
    // 函数从未抛出异常，返回指令本身也会触发一次展开查询。
    //
    // 因此 .xdata 必须复制进新页，UnwindData 改指副本的偏移。副本放在
    // 被映射代码之后，与新页同基址，RVA 天然成立。
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

        // .xdata 副本放在被映射代码之后。新页按页对齐分配，函数本体
        // 通常远小于一页，尾部空间足够；不够时整块拒绝，而不是产出
        // 一份展开器无法解析的表。
        const std::size_t xdata_base = align_up(region_size_, 4);
        std::size_t xdata_used = 0;

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

        // 复制每个表项引用到的展开数据，并把 UnwindData 改指副本
        for (std::size_t i = 0; i < cursor; ++i) {
            const std::size_t bytes =
                unwind_info_size(entries[i].UnwindData, layout);
            if (bytes == 0)
                continue;

            const std::size_t at = xdata_base + xdata_used;
            if (at + bytes > mapped_size_)
                break;  // 新页放不下，该条目不登记展开信息

            const auto* original = reinterpret_cast<const std::uint8_t*>(
                layout.base + entries[i].UnwindData);
            for (std::size_t k = 0; k < bytes; ++k)
                mapped_[at + k] = original[k];

            entries[i].UnwindData = static_cast<DWORD>(at);
            xdata_used += bytes;
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

    static std::size_t align_up(std::size_t value, std::size_t to) noexcept {
        return ((value + to - 1) / to) * to;
    }

    // UNWIND_INFO 是变长结构：头部四字节之后跟 CountOfCodes 个两字节的
    // 展开码，再按需跟对齐填充、异常处理函数指针与链式条目。
    // 只算出需要复制的字节数，不做语义解析。
    //
    // 边界全部用整数比较。UnwindData 来自映像数据，被改写后会变成
    // 任意值，用指针算术判断越界本身就是未定义行为。
    static std::size_t unwind_info_size(std::uint32_t unwind_rva,
                                        const ImageLayout& layout) noexcept {
        const auto base = reinterpret_cast<std::uintptr_t>(layout.base);
        const auto end = base + layout.size_of_image;
        const auto at = base + unwind_rva;

        if (at < base || at + 4 > end)
            return 0;

        const auto* info = reinterpret_cast<const std::uint8_t*>(at);

        const std::uint8_t version = info[0] & 0x07;
        const std::uint8_t flags = static_cast<std::uint8_t>(info[0] >> 3);
        const std::uint8_t codes = info[2];

        if (version != 1)
            return 0;

        std::size_t size = 4 + static_cast<std::size_t>(codes) * 2;

        if ((flags & 0x04) != 0)
            size += 12;
        else if ((flags & 0x03) != 0)
            size = align_up(size, 4) + 4;

        if (size > layout.size_of_image || at + size > end)
            return 0;

        return size;
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

namespace veil::platform {

// 把函数映射到私有页后按原签名调用。//
// RemappedCode 只负责复制与修正，调用约定由模板参数给出。这样同一个
// 封装既能承载派生入口这类有返回值的函数，也能承载返回 void 的写入
// 函数，不必为每种签名各写一遍。
//
// 映射成功前 entry() 返回 nullptr，因此调用方要先确认 armed()。未映射
// 时直接用原函数指针是安全的：副本与原件行为一致，只是断点与补丁的
// 落点不同。
template <typename Fn>
class RemappedCall {
public:
    RemappedCall() noexcept = default;
    ~RemappedCall() noexcept { release(); }

    RemappedCall(const RemappedCall&) = delete;
    RemappedCall& operator=(const RemappedCall&) = delete;

    // 映射 target 指向的函数。module 通常是本模块基址。
    bool arm(const void* module, Fn target) noexcept {
        origin_ = target;
        const bool mapped = code_.map_function(
            module, reinterpret_cast<const void*>(target));
        if (mapped)
            mapped_ = reinterpret_cast<Fn>(code_.entry());
        return mapped;
    }

    bool armed() const noexcept { return mapped_ != nullptr; }

    // 可调用地址。未映射时回落到原函数。
    Fn entry() const noexcept { return mapped_ != nullptr ? mapped_ : origin_; }

    void release() noexcept {
        code_.release();
        mapped_ = nullptr;
        origin_ = nullptr;
    }

private:
    RemappedCode code_;
    Fn mapped_ = nullptr;
    Fn origin_ = nullptr;
};

}  // namespace veil::platform
