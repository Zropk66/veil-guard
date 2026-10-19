#pragma once

#include "../config.hpp"
#include "../detail/mix.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::platform {

// 由独立汇编单元提供，MSVC 与 MinGW 各一份。
extern "C" long veil_syscall_stub(std::uint32_t number,
                                  std::uintptr_t a1, std::uintptr_t a2,
                                  std::uintptr_t a3, std::uintptr_t a4,
                                  std::uintptr_t a5, std::uintptr_t a6);

namespace detail {

struct ExportRange {
    const std::uint8_t* base;
    const std::uint32_t* names;
    const std::uint16_t* ordinals;
    const std::uint32_t* functions;
    std::uint32_t count;
};

inline bool locate_exports(ExportRange* out) noexcept {
    const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == nullptr)
        return false;

    const auto* base = reinterpret_cast<const std::uint8_t*>(ntdll);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + static_cast<std::ptrdiff_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    const IMAGE_DATA_DIRECTORY dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0)
        return false;

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        base + dir.VirtualAddress);
    if (exports->NumberOfNames == 0 || exports->NumberOfNames > 8192)
        return false;

    out->base = base;
    out->names = reinterpret_cast<const std::uint32_t*>(
        base + exports->AddressOfNames);
    out->ordinals = reinterpret_cast<const std::uint16_t*>(
        base + exports->AddressOfNameOrdinals);
    out->functions = reinterpret_cast<const std::uint32_t*>(
        base + exports->AddressOfFunctions);
    out->count = exports->NumberOfNames;
    return true;
}

inline bool name_equals(const char* a, const char* b) noexcept {
    std::size_t i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i])
            return false;
        ++i;
    }
    return a[i] == '\0' && b[i] == '\0';
}

// 从 stub 前导取 SSN。Nt* 与 Zw* 指向同一段代码，因此两者都能命中；
// 当 Nt* 的 stub 被改写为跳转时，调用方可以改查 Zw* 同名导出。
inline bool stub_number(const ExportRange& range, const char* export_name,
                        std::uint32_t* out) noexcept {
    for (std::uint32_t i = 0; i < range.count; ++i) {
        const char* name =
            reinterpret_cast<const char*>(range.base + range.names[i]);
        if (!name_equals(name, export_name))
            continue;

        const std::uint16_t ordinal = range.ordinals[i];
        const auto* stub = range.base + range.functions[ordinal];

        // mov r10, rcx
        if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1)
            return false;
        // mov eax, imm32
        if (stub[3] != 0xB8)
            return false;

        const std::uint32_t number =
            static_cast<std::uint32_t>(stub[4]) |
            (static_cast<std::uint32_t>(stub[5]) << 8) |
            (static_cast<std::uint32_t>(stub[6]) << 16) |
            (static_cast<std::uint32_t>(stub[7]) << 24);

        // 合理 SSN 远小于该上界，越界说明读到了被改写的内容
        if (number == 0 || number >= 0x2000)
            return false;

        *out = number;
        return true;
    }
    return false;
}

inline const char* zw_alias(const char* export_name) noexcept {
    static thread_local char buffer[128];
    if (export_name[0] != 'N' || export_name[1] != 't')
        return nullptr;

    std::size_t i = 0;
    buffer[i++] = 'Z';
    buffer[i++] = 'w';
    for (std::size_t k = 2; k < sizeof(buffer) - 1 && export_name[k] != '\0'; ++k)
        buffer[i++] = export_name[k];
    buffer[i] = '\0';
    return buffer;
}

}  // namespace detail

// 解析系统调用号。
//
// 不按导出名表序号推导：ntdll 的导出表混有大量非 syscall 导出，
// 例如 Rtl* 与 __chkstk，名字表索引与 SSN 并不对应。这里读 stub
// 前导的 `mov eax, imm32`，并在 Nt* stub 被 inline hook 时改查
// 同名 Zw* 导出，两者指向同一段代码。
inline std::uint32_t syscall_number(const char* export_name) noexcept {
    if (export_name == nullptr || export_name[0] == '\0')
        return 0;

    detail::ExportRange range{};
    if (!detail::locate_exports(&range))
        return 0;

    std::uint32_t number = 0;
    if (detail::stub_number(range, export_name, &number))
        return number;

    if (const char* alias = detail::zw_alias(export_name))
        if (detail::stub_number(range, alias, &number))
            return number;

    return 0;
}

// x64 syscall 直发。参数按 Windows x64 调用约定传入，汇编桩负责把它们
// 搬进 r10/rcx/rdx/r8/r9 以及两个栈上槽位。第六个参数只在少数调用中用到，
// 但必须存在：缺省时该位置会残留调用方自己的栈数据，被内核当作指针解引用。
inline long syscall_direct(std::uint32_t number,
                           std::uintptr_t a1, std::uintptr_t a2,
                           std::uintptr_t a3, std::uintptr_t a4,
                           std::uintptr_t a5, std::uintptr_t a6) noexcept {
    return veil_syscall_stub(number, a1, a2, a3, a4, a5, a6);
}

}  // namespace veil::platform
