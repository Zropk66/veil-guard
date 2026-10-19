#pragma once

#include "../config.hpp"

#include <concepts>
#include <cstddef>

namespace veil {

struct Observation {
    const void* data;
    std::size_t size;
};

// provider 只输出原始观测字节。正常环境下这些字节必须全为零，
// 否则服务端需要登记期望值，违背零登记设计。
//
// 概念按实例调用表述，静态 observe 的 provider 同样满足：静态成员
// 可以经由 const 实例调用。这样带状态的 provider 与无状态的 provider
// 能以同一种方式进入证据布局。
template <typename Provider>
concept ProviderLike = requires(const Provider& instance) {
    { Provider::OBSERVATION_SIZE } -> std::convertible_to<std::size_t>;
    { instance.observe() } -> std::same_as<Observation>;
};

}  // namespace veil
