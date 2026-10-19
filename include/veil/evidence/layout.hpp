#pragma once

#include "../config.hpp"
#include "../detail/observe.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::evidence {

// 按声明顺序拼接 provider 观测。
//
// 顺序与内容在编译期确定，无运行时分发、无中心注册表。消费者改动顺序
// 或增删 provider 后，服务端必须同步，否则派生分叉。
//
// 序列化接收 provider 实例：无状态 provider 直接传入默认构造的对象，
// 带状态的 provider 由调用方在外部完成登记后传入。
template <typename... Providers>
class Layout {
public:
    static_assert((ProviderLike<Providers> && ...),
                  "every layout member must satisfy ProviderLike");

    static constexpr std::size_t SIZE = (Providers::OBSERVATION_SIZE + ... + 0);

    static_assert(SIZE <= MAX_EVIDENCE_BYTES,
                  "evidence blob exceeds the configured maximum");

    static bool serialize(std::uint8_t* out, std::size_t capacity,
                          const Providers&... providers) noexcept {
        if (out == nullptr || capacity < SIZE)
            return false;

        std::size_t cursor = 0;
        const bool ok = (append<Providers>(out, cursor, providers) && ...);
        return ok;
    }

private:
    template <typename Provider>
    static bool append(std::uint8_t* out, std::size_t& cursor,
                       const Provider& provider) noexcept {
        const Observation observation = provider.observe();
        if (observation.data == nullptr ||
            observation.size != Provider::OBSERVATION_SIZE)
            return false;

        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
        for (std::size_t i = 0; i < observation.size; ++i)
            out[cursor + i] = bytes[i];
        cursor += observation.size;
        return true;
    }
};

}  // namespace veil::evidence
