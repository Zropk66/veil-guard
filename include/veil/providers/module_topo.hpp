#pragma once

#include "../config.hpp"
#include "../detail/mix.hpp"
#include "../detail/observe.hpp"
#include "../platform/peb.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::providers {

// 模块拓扑观测。
//
// 破解包的注入顺序是先在宿主里驻留代理 DLL，再注入目标模块。因此
// 存在非系统目录、非同目录的模块即说明环境已被污染。
//
// 输出的是计数与路径哈希累积，不是「是否可信」。路径哈希用 XOR 累积，
// 单个模块被移除或替换都会让累积值改变。
class ModuleTopology {
public:
    static constexpr std::size_t OBSERVATION_SIZE =
        sizeof(std::uint32_t) + 16;

    struct ObservationBuffer {
        std::uint32_t foreign_count;
        std::uint8_t path_hash_xor[16];
    };

    static_assert(sizeof(ObservationBuffer) == OBSERVATION_SIZE,
                  "observation buffer must be tightly packed");

    // 前缀匹配，且要求可信前缀之后紧跟分隔符或字符串结束。
    // 纯子串匹配会把 c:\temp\x\system32\evil.dll 判为可信；前缀匹配但
    // 不检查分隔符则会把 c:\windows\system32evil\x.dll 判为可信。
    //
    // 系统前缀从 GetSystemDirectoryW 与 GetWindowsDirectoryW 现取，
    // 不硬编码 c:\windows。Windows 装在非 C 盘时硬编码会让全部系统
    // 模块被判为外源。
    static bool is_path_trusted(const wchar_t* path,
                                std::uint32_t path_length) noexcept {
        if (path == nullptr || path_length == 0)
            return false;

        wchar_t prefix[MAX_PATH];

        DWORD written = GetSystemDirectoryW(prefix, MAX_PATH);
        if (written > 0 && written < MAX_PATH) {
            if (length_prefix_match(path, path_length, prefix,
                                    static_cast<std::uint32_t>(written)))
                return true;
        }

        written = GetWindowsDirectoryW(prefix, MAX_PATH);
        if (written > 0 && written < MAX_PATH) {
            // 系统目录之外还有 winsxs 与 systemapps 两处
            static const wchar_t* const kSuffixes[] = {
                L"\\winsxs",
                L"\\systemapps",
            };
            for (const wchar_t* suffix : kSuffixes) {
                std::size_t cursor = written;
                for (std::size_t k = 0; suffix[k] != L'\0' &&
                                       cursor < MAX_PATH - 1; ++k)
                    prefix[cursor++] = suffix[k];
                prefix[cursor] = L'\0';
                if (length_prefix_match(path, path_length, prefix,
                                        static_cast<std::uint32_t>(cursor)))
                    return true;
            }
        }

        // 与自身模块同目录的文件视为可信。这里用「目录部分与自身一致」
        // 判定，而不是对路径做子串匹配。
        return is_same_directory_as_self(path, path_length);
    }

    Observation observe() const noexcept {
        ObservationBuffer buffer{};

        const std::size_t count = platform::module_count();
        for (std::size_t i = 0; i < count; ++i) {
            platform::ModuleInfo info{};
            if (!platform::module_at(i, &info))
                continue;
            if (is_path_trusted(info.path, info.path_length))
                continue;

            ++buffer.foreign_count;

            std::uint64_t hash = 0xCBF29CE484222325ULL;
            for (std::uint32_t k = 0; k < info.path_length; ++k)
                hash = (hash ^ static_cast<std::uint64_t>(info.path[k])) *
                       0x100000001B3ULL;

            for (std::size_t b = 0; b < 8; ++b) {
                buffer.path_hash_xor[b] ^= static_cast<std::uint8_t>(hash >> (b * 8));
                buffer.path_hash_xor[8 + b] ^=
                    static_cast<std::uint8_t>(hash >> ((b + 8) * 8));
            }
        }

        static thread_local ObservationBuffer slot;
        slot = buffer;
        return Observation{&slot, OBSERVATION_SIZE};
    }

private:
    // 前缀相等，且前缀之后是分隔符或字符串结束
    static bool length_prefix_match(const wchar_t* path,
                                    std::uint32_t path_length,
                                    const wchar_t* prefix,
                                    std::uint32_t prefix_length) noexcept {
        if (prefix_length == 0 || prefix_length > path_length)
            return false;

        for (std::uint32_t i = 0; i < prefix_length; ++i) {
            if (platform::lower_ascii(path[i]) != platform::lower_ascii(prefix[i]))
                return false;
        }

        if (prefix_length == path_length)
            return true;

        const wchar_t next = path[prefix_length];
        return next == L'\\' || next == L'/';
    }

    static bool is_same_directory_as_self(const wchar_t* path,
                                          std::uint32_t path_length) noexcept {
        wchar_t self[MAX_PATH];
        const DWORD written = GetModuleFileNameW(nullptr, self, MAX_PATH);
        if (written == 0 || written >= MAX_PATH)
            return false;

        std::uint32_t self_dir = written;
        while (self_dir > 0 && self[self_dir - 1] != L'\\' && self[self_dir - 1] != L'/')
            --self_dir;
        if (self_dir == 0)
            return false;

        std::uint32_t path_dir = path_length;
        while (path_dir > 0 && path[path_dir - 1] != L'\\' && path[path_dir - 1] != L'/')
            --path_dir;

        if (self_dir != path_dir)
            return false;

        for (std::uint32_t i = 0; i < self_dir; ++i) {
            if (platform::lower_ascii(self[i]) != platform::lower_ascii(path[i]))
                return false;
        }
        return true;
    }
};

static_assert(ProviderLike<ModuleTopology>);

}  // namespace veil::providers
