#pragma once

#include "../config.hpp"
#include "syscall.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::platform {

struct RegionInfo {
    void* base;
    std::uintptr_t allocation_base;
    std::uint32_t size;
    std::uint32_t state;
    std::uint32_t protect;
    std::uint32_t type;
};

// 走 NtQueryVirtualMemory 而非 VirtualQuery。后者是 kernel32 导出，
// 改写其 IAT 槽位即可让全部区间内省返回伪造结果。
inline bool query_region(const void* address, RegionInfo* out) noexcept {
    if (address == nullptr || out == nullptr)
        return false;

    const std::uint32_t ssn = syscall_number("NtQueryVirtualMemory");
    if (ssn == 0)
        return false;

    struct MemoryBasicInformation {
        void* base;
        void* allocation_base;
        std::uint32_t allocation_protect;
        std::uint32_t partition_id;
        std::uintptr_t region_size;
        std::uint32_t state;
        std::uint32_t protect;
        std::uint32_t type;
    };

    MemoryBasicInformation mbi{};
    const long status = syscall_direct(
        ssn,
        static_cast<std::uintptr_t>(
            reinterpret_cast<std::uintptr_t>(GetCurrentProcess())),
        static_cast<std::uintptr_t>(
            reinterpret_cast<std::uintptr_t>(address)),
        0,
        reinterpret_cast<std::uintptr_t>(&mbi),
        sizeof(mbi),
        0);

    if (status != 0)
        return false;

    out->base = mbi.base;
    out->allocation_base = reinterpret_cast<std::uintptr_t>(mbi.allocation_base);
    out->size = static_cast<std::uint32_t>(mbi.region_size);
    out->state = mbi.state;
    out->protect = mbi.protect;
    out->type = mbi.type;
    return true;
}

// 页面是否具备写权限。供 provider 判定区间属性。
inline bool is_writable(const RegionInfo& info) noexcept {
    const std::uint32_t p = info.protect & 0xFFu;
    return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

inline bool is_executable(const RegionInfo& info) noexcept {
    const std::uint32_t p = info.protect & 0xFFu;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

// PAGE_GUARD 不改变 RWX 位，只作为一个附加标志存在，因此必须单独判断。
inline bool is_guarded(const RegionInfo& info) noexcept {
    return (info.protect & PAGE_GUARD) != 0;
}

inline bool is_committed(const RegionInfo& info) noexcept {
    return info.state == MEM_COMMIT;
}

// 只读内省：供遍历异常结构与链表时校验目标地址可解引用，
// 避免解法器中途被改成不可读区间导致访问违规。
inline bool is_readable(const void* address) noexcept {
    RegionInfo info{};
    if (!query_region(address, &info))
        return false;
    if (!is_committed(info))
        return false;

    const std::uint32_t p = info.protect & 0xFFu;
    return p != PAGE_NOACCESS && p != PAGE_GUARD;
}

// 全地址空间遍历。NtQueryVirtualMemory 对空闲区间同样返回结果，
// 因此可以按返回的 region_size 连续推进，无需试探步长。
struct RegionWalker {
    std::uintptr_t cursor = 0x10000;
    std::size_t visited = 0;

    // 用户态地址上限。内核侧区间在内省时会被系统拒绝，无需主动规避。
    static constexpr std::uintptr_t LIMIT = 0x00007FFFFFFF0000ULL;
    static constexpr std::size_t MAX_REGIONS = 1u << 17;

    bool next(RegionInfo* out) noexcept {
        while (cursor < LIMIT && visited < MAX_REGIONS) {
            RegionInfo info{};
            if (!query_region(reinterpret_cast<const void*>(cursor), &info)) {
                // 该地址落在内省范围之外，直接跳到下一段
                cursor += 0x1000;
                continue;
            }

            const std::uintptr_t base =
                reinterpret_cast<std::uintptr_t>(info.base);
            std::uintptr_t advance = info.size;
            if (advance == 0 || base + advance <= cursor)
                advance = 0x1000;

            cursor = base + advance;
            ++visited;

            if (out != nullptr)
                *out = info;
            return true;
        }
        return false;
    }
};

}  // namespace veil::platform
