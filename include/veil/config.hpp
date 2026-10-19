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

// 证据 blob 的硬上限。全部 provider 的顺序拼接与域字节都需落在此范围内，
// Binder 的 info 缓冲因此取该值加一，hkdf 的截断阈值必须再高出一档。
inline constexpr std::size_t MAX_EVIDENCE_BYTES = 1024;

// 标准证据布局的长度，对外契约。
//
// 服务端按同一长度用零基线构造 info。客户端改动 provider 组合后服务端
// 必须同步，否则全部客户端派生分叉。该值由 guard_impl.cpp 的静态断言
// 与标准布局锁定。
inline constexpr std::size_t STANDARD_EVIDENCE_SIZE = 68;

}  // namespace veil
