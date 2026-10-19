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

// 含代码完整性 provider 的布局长度。
//
// 服务端登记表里对应布局 2。客户端启用这套布局时必须在请求中声明
// 布局标识，否则服务端按默认布局派生，两侧密钥不同。
inline constexpr std::size_t INTEGRITY_EVIDENCE_SIZE = 328;

// 布局标识。与服务端 EVIDENCE_LAYOUTS 的键一一对应。
//
// 客户端通过请求字段 evidenceLayout 声明，服务端据此选择零基线长度。
// 未登记的标识会被拒绝。
inline constexpr const char* EVIDENCE_LAYOUT_STANDARD = "1";
inline constexpr const char* EVIDENCE_LAYOUT_INTEGRITY = "2";

}  // namespace veil
