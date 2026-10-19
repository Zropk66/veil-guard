#pragma once

#include "../config.hpp"
#include "../crypto/hkdf.hpp"
#include "../crypto/hmac.hpp"
#include "../detail/common.hpp"
#include "payload.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::license {

inline constexpr std::size_t NONCE_SIZE = 16;
inline constexpr std::size_t BINDING_SIZE = 16;
inline constexpr std::size_t SIGNATURE_SIZE = 64;
inline constexpr std::size_t MAX_MACHINE_ID = 127;
inline constexpr std::size_t MAX_BINDING_MESSAGE = 8192;
inline constexpr std::uint8_t DOMAIN_KEYSTREAM = 0x01;
inline constexpr std::uint8_t DOMAIN_BINDING = 0x02;

// 机器标识参与派生，而不是参与独立比对。
//
// 机器不符时绑定校验不同，签名自然验不过，因此不存在「机器是否匹配」
// 这样可被单点 patch 的分支。校验值由客户端本地算出，不随包传输，
// 攻击者没有可剥离的字段来退回无绑定模式。
//
// 超长标识显式失败。截断会让两台前缀相同的机器派生出同一密钥。
inline bool derive_machine_key(const void* card_key, std::size_t card_key_len,
                               const void* nonce, std::size_t nonce_len,
                               const void* machine_id, std::size_t machine_id_len,
                               std::uint8_t domain,
                               void* out, std::size_t out_len) noexcept {
    if (card_key == nullptr || card_key_len == 0)
        return false;
    if (nonce == nullptr || nonce_len == 0)
        return false;
    if (out == nullptr || out_len == 0)
        return false;
    if (machine_id_len > MAX_MACHINE_ID)
        return false;
    if (machine_id == nullptr && machine_id_len != 0)
        return false;

    std::uint8_t info[MAX_MACHINE_ID + 1];
    std::size_t info_len = 0;
    const auto* id = static_cast<const std::uint8_t*>(machine_id);
    for (std::size_t i = 0; i < machine_id_len; ++i)
        info[info_len++] = id[i];
    info[info_len++] = domain;

    hkdf_sha256(card_key, card_key_len, nonce, nonce_len,
                info, info_len, out, out_len);

    detail::secure_wipe(info, sizeof(info));
    return true;
}

// 原地异或密钥流。加密与解密是同一操作。
inline bool xor_stream(const void* card_key, std::size_t card_key_len,
                       const void* nonce,
                       const void* machine_id, std::size_t machine_id_len,
                       void* payload, std::size_t payload_len) noexcept {
    if (payload == nullptr || payload_len == 0)
        return false;

    std::uint8_t keystream_key[32];
    if (!derive_machine_key(card_key, card_key_len, nonce, NONCE_SIZE,
                            machine_id, machine_id_len,
                            DOMAIN_KEYSTREAM, keystream_key,
                            sizeof(keystream_key)))
        return false;

    std::uint8_t stream[512];
    if (payload_len > sizeof(stream)) {
        detail::secure_wipe(keystream_key, sizeof(keystream_key));
        return false;
    }

    hkdf_sha256(keystream_key, sizeof(keystream_key), nonce, NONCE_SIZE,
                nullptr, 0, stream, payload_len);

    auto* bytes = static_cast<std::uint8_t*>(payload);
    for (std::size_t i = 0; i < payload_len; ++i)
        bytes[i] ^= stream[i];

    detail::secure_wipe(keystream_key, sizeof(keystream_key));
    detail::secure_wipe(stream, sizeof(stream));
    return true;
}

// 绑定校验 = HMAC(HKDF(卡密, nonce, HWID ‖ 域), nonce ‖ 密文) 前 16 字节。
inline bool compute_binding(const void* card_key, std::size_t card_key_len,
                            const void* nonce,
                            const void* machine_id, std::size_t machine_id_len,
                            const void* cipher, std::size_t cipher_len,
                            std::uint8_t out[BINDING_SIZE]) noexcept {
    if (nonce == nullptr || out == nullptr)
        return false;
    if (cipher == nullptr && cipher_len != 0)
        return false;
    if (cipher_len + NONCE_SIZE > MAX_BINDING_MESSAGE)
        return false;

    std::uint8_t binding_key[32];
    if (!derive_machine_key(card_key, card_key_len, nonce, NONCE_SIZE,
                            machine_id, machine_id_len,
                            DOMAIN_BINDING, binding_key, sizeof(binding_key)))
        return false;

    std::uint8_t message[MAX_BINDING_MESSAGE];
    for (std::size_t i = 0; i < NONCE_SIZE; ++i)
        message[i] = static_cast<const std::uint8_t*>(nonce)[i];
    for (std::size_t i = 0; i < cipher_len; ++i)
        message[NONCE_SIZE + i] = static_cast<const std::uint8_t*>(cipher)[i];

    std::uint8_t digest[32];
    Hmac::compute(binding_key, sizeof(binding_key), message,
                  NONCE_SIZE + cipher_len, digest);

    for (std::size_t i = 0; i < BINDING_SIZE; ++i)
        out[i] = digest[i];

    detail::secure_wipe(binding_key, sizeof(binding_key));
    detail::secure_wipe(message, NONCE_SIZE + cipher_len);
    detail::secure_wipe(digest, sizeof(digest));
    return true;
}

}  // namespace veil::license
