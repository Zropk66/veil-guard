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

}  // namespace veil::platform
