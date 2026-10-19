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
template <typename Provider>
concept ProviderLike = requires {
    { Provider::OBSERVATION_SIZE } -> std::convertible_to<std::size_t>;
    { Provider::observe() } -> std::same_as<Observation>;
};

}  // namespace veil
