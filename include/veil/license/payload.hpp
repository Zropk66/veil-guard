#pragma once

#include "../config.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace veil::license {

// 载荷对库不透明。库只要求长度可确定、字段可读取时效与功能位。
template <typename T>
concept PayloadLike = requires(const T& payload) {
    { sizeof(T) } -> std::convertible_to<std::size_t>;
    { payload.issued_at } -> std::convertible_to<std::uint64_t>;
    { payload.expires_at } -> std::convertible_to<std::uint64_t>;
    { payload.feature_mask } -> std::convertible_to<std::uint32_t>;
    requires std::is_trivially_copyable_v<T>;
};

// 时效折算。过期或时钟异常返回 0，调用方无需另设「是否过期」分支。
// 单一判定点正是被 patch 的目标，因此不提供独立的过期检查接口。
template <PayloadLike T>
VEIL_FORCEINLINE std::uint32_t effective_mask(const T& payload,
                                              std::int64_t now_ms) noexcept {
    if (payload.expires_at != 0) {
        const auto expires = static_cast<std::int64_t>(payload.expires_at);
        if (expires <= now_ms)
            return 0;
    }

    const auto issued = static_cast<std::int64_t>(payload.issued_at);
    if (issued > now_ms + 3600LL * 1000LL)
        return 0;

    return payload.feature_mask;
}

}  // namespace veil::license
