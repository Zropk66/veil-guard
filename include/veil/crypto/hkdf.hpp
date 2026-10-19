#pragma once

#include "hmac.hpp"
#include "sha256.hpp"

#include <cstddef>
#include <cstdint>

namespace veil {

// info 超过该长度即截断。该常量是 RFC 5869 之外的自定界限，
// 用于固定 expand 阶段的栈上缓冲，不作为安全边界使用。
inline constexpr std::size_t HKDF_MAX_INFO = 1024;

// RFC 5869。expand 阶段必须以 PRK 作为 HMAC 密钥，退回裸 SHA256
// 会让不同盐派生出相同的密钥流。
inline void hkdf_sha256(const void* ikm, std::size_t ikm_len,
                        const void* salt, std::size_t salt_len,
                        const void* info, std::size_t info_len,
                        void* out, std::size_t out_len) noexcept {
    std::uint8_t prk[Sha256::DIGEST_SIZE];
    Hmac::compute(salt_len > 0 ? salt : ikm, salt_len > 0 ? salt_len : ikm_len,
                  ikm, ikm_len, prk);

    auto* output = static_cast<std::uint8_t*>(out);
    std::uint8_t block[Sha256::DIGEST_SIZE];
    std::uint8_t previous[Sha256::DIGEST_SIZE];
    std::size_t previous_len = 0;
    std::uint8_t counter = 1;

    while (out_len > 0) {
        std::uint8_t message[Sha256::DIGEST_SIZE + HKDF_MAX_INFO + 1];
        std::size_t message_len = 0;
        for (std::size_t i = 0; i < previous_len; ++i)
            message[message_len++] = previous[i];

        const std::size_t info_copy = info_len < HKDF_MAX_INFO ? info_len
                                                              : HKDF_MAX_INFO;
        const auto* info_bytes = static_cast<const std::uint8_t*>(info);
        for (std::size_t i = 0; i < info_copy; ++i)
            message[message_len++] = info_bytes[i];

        message[message_len++] = counter;

        Hmac::compute(prk, Sha256::DIGEST_SIZE, message, message_len, block);

        const std::size_t take =
            out_len < Sha256::DIGEST_SIZE ? out_len : Sha256::DIGEST_SIZE;
        for (std::size_t i = 0; i < take; ++i)
            output[i] = block[i];

        for (std::size_t i = 0; i < Sha256::DIGEST_SIZE; ++i)
            previous[i] = block[i];
        previous_len = Sha256::DIGEST_SIZE;

        output += take;
        out_len -= take;
        ++counter;
    }

    detail::secure_wipe(prk, sizeof(prk));
    detail::secure_wipe(block, sizeof(block));
    detail::secure_wipe(previous, sizeof(previous));
}

}  // namespace veil
