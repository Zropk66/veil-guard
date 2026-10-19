#pragma once

#include "../config.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>
#include <winternl.h>

namespace veil::platform {

// 部分 SDK 未导出 LDR_DATA_TABLE_ENTRY 的完整字段布局，
// 这里按公开的 PEB 结构自行声明，避免依赖工具链差异。
struct LdrEntry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

struct ModuleInfo {
    void* base;
    std::uint32_t size;
    const wchar_t* path;
    std::uint32_t path_length;
};

VEIL_FORCEINLINE PPEB peb() noexcept {
    return reinterpret_cast<PPEB>(__readgsqword(0x60));
}

inline std::size_t module_count() noexcept {
    PPEB p = peb();
    if (p == nullptr || p->Ldr == nullptr)
        return 0;

    std::size_t count = 0;
    LIST_ENTRY* head = &p->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* entry = head->Flink; entry != head && entry != nullptr;
         entry = entry->Flink) {
        if (++count > 4096)
            break;
    }
    return count;
}

inline bool module_at(std::size_t index, ModuleInfo* out) noexcept {
    if (out == nullptr)
        return false;

    PPEB p = peb();
    if (p == nullptr || p->Ldr == nullptr)
        return false;

    std::size_t cursor = 0;
    LIST_ENTRY* head = &p->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* entry = head->Flink; entry != head && entry != nullptr;
         entry = entry->Flink) {
        if (cursor == index) {
            auto* node = CONTAINING_RECORD(entry, LdrEntry, InMemoryOrderLinks);
            out->base = node->DllBase;
            out->size = node->SizeOfImage;
            out->path = node->FullDllName.Buffer;
            out->path_length = node->FullDllName.Length / sizeof(wchar_t);
            return out->base != nullptr && out->path != nullptr;
        }
        ++cursor;
        if (cursor > 4096)
            break;
    }
    return false;
}

inline wchar_t lower_ascii(wchar_t c) noexcept {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + (L'a' - L'A')) : c;
}

inline bool contains_ci(const wchar_t* haystack, std::uint32_t haystack_len,
                        const wchar_t* needle) noexcept {
    if (haystack == nullptr || needle == nullptr)
        return false;

    std::uint32_t needle_len = 0;
    while (needle[needle_len] != L'\0')
        ++needle_len;
    if (needle_len == 0 || needle_len > haystack_len)
        return false;

    for (std::uint32_t start = 0; start + needle_len <= haystack_len; ++start) {
        bool matched = true;
        for (std::uint32_t i = 0; i < needle_len; ++i) {
            if (lower_ascii(haystack[start + i]) != lower_ascii(needle[i])) {
                matched = false;
                break;
            }
        }
        if (matched)
            return true;
    }
    return false;
}

inline bool starts_with_ci(const wchar_t* path, std::uint32_t path_len,
                           const wchar_t* prefix) noexcept {
    if (path == nullptr || prefix == nullptr)
        return false;

    std::uint32_t prefix_len = 0;
    while (prefix[prefix_len] != L'\0')
        ++prefix_len;
    if (prefix_len > path_len)
        return false;

    for (std::uint32_t i = 0; i < prefix_len; ++i) {
        if (lower_ascii(path[i]) != lower_ascii(prefix[i]))
            return false;
    }
    return true;
}

inline void* module_base_ci(const wchar_t* name) noexcept {
    if (name == nullptr)
        return nullptr;

    std::uint32_t name_len = 0;
    while (name[name_len] != L'\0')
        ++name_len;

    const std::size_t count = module_count();
    for (std::size_t i = 0; i < count; ++i) {
        ModuleInfo info{};
        if (!module_at(i, &info))
            continue;
        if (info.path_length < name_len)
            continue;

        // 只比较文件名部分，避免把路径中恰好包含目标名的目录误命中
        const wchar_t* tail = info.path + (info.path_length - name_len);
        bool matched = true;
        for (std::uint32_t k = 0; k < name_len; ++k) {
            if (lower_ascii(tail[k]) != lower_ascii(name[k])) {
                matched = false;
                break;
            }
        }
        if (matched)
            return info.base;
    }
    return nullptr;
}

}  // namespace veil::platform
