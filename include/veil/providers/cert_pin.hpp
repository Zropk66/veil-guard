#pragma once

#include "../config.hpp"
#include "../detail/observe.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::providers {

// 对端证书公钥指纹观测。
//
// 只返回实测值，不与任何预期值比对。服务端以自己的证书做同样的派生，
// 指纹不符时两侧派生出不同密钥，AEAD 解不开。没有可比对的布尔量。
//
// 未走 TLS 时为零值，派生结果与任何正常服务端都不一致，等价于拒绝。
class CertificatePin {
public:
    static constexpr std::size_t OBSERVATION_SIZE = 32;

    struct ObservationBuffer {
        std::uint8_t spki_digest[32];
    };

    static_assert(sizeof(ObservationBuffer) == OBSERVATION_SIZE,
                  "observation buffer must be tightly packed");

    CertificatePin() noexcept = default;

    explicit CertificatePin(const std::uint8_t digest[32]) noexcept {
        if (digest != nullptr)
            for (std::size_t i = 0; i < 32; ++i)
                buffer_.spki_digest[i] = digest[i];
    }

    void set_digest(const std::uint8_t digest[32]) noexcept {
        buffer_ = ObservationBuffer{};
        if (digest != nullptr)
            for (std::size_t i = 0; i < 32; ++i)
                buffer_.spki_digest[i] = digest[i];
    }

    Observation observe() const noexcept {
        return Observation{&buffer_, OBSERVATION_SIZE};
    }

private:
    ObservationBuffer buffer_{};
};

static_assert(ProviderLike<CertificatePin>);

}  // namespace veil::providers
