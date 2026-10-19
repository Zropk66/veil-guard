#pragma once

#include <cstddef>
#include <cstdint>

#if !defined(_WIN32) || !defined(_M_X64)
#error "veil requires Windows x64"
#endif

#if !defined(VEIL_BUILD_SEED)
#error "VEIL_BUILD_SEED must be defined by the build system"
#endif

#if defined(_MSC_VER)
#define VEIL_FORCEINLINE __forceinline
#define VEIL_NOINLINE __declspec(noinline)
#else
#define VEIL_FORCEINLINE inline __attribute__((always_inline))
#define VEIL_NOINLINE __attribute__((noinline))
#endif

namespace veil {

// 构建种子参与全部编译期常量派生，使不同构建的机器码特征互不通用。
// 由 CMake 显式注入，缺省时构建期已发出警告。
inline constexpr std::uint64_t BUILD_SEED =
    static_cast<std::uint64_t>(VEIL_BUILD_SEED);

// 观测槽位上限。区域数、模块数等 provider 都以此为界。
inline constexpr std::size_t MAX_OBSERVATION_SLOTS = 8;

// 证据 blob 的硬上限。hkdf 的 info 拼接缓冲需同时容纳证据与域字节，
// 因此该值必须留出余量，不能让 info 触到 hkdf 的截断阈值。
inline constexpr std::size_t MAX_EVIDENCE_BYTES = 512;

}  // namespace veil
