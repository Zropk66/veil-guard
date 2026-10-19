#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

extern "C" {
// Monocypher 是 C99 代码，需以 C 链接方式引入，避免 C++ 名称修饰
// 导致链接期找不到符号。
int crypto_ed25519_check(const uint8_t signature[64],
                         const uint8_t public_key[32],
                         const uint8_t* message, size_t message_size);
}

namespace veil {

// RFC 8032 验签。系统 CNG 不提供 Ed25519，故由 Monocypher 承担。
// 选 RFC 8032 而非 Monocypher 顶层 BLAKE2b EdDSA 变体，是因为服务端
// Node crypto.sign(null, ...) 产出 SHA-512 版本，两者不互通。
class Ed25519 {
public:
    static constexpr std::size_t PUBLIC_KEY_SIZE = 32;
    static constexpr std::size_t SIGNATURE_SIZE = 64;

    bool set_public_key(const std::uint8_t* public_key,
                        std::size_t length) noexcept {
        if (public_key == nullptr || length != PUBLIC_KEY_SIZE) {
            loaded_ = false;
            return false;
        }

        for (std::size_t i = 0; i < PUBLIC_KEY_SIZE; ++i)
            public_key_[i] = public_key[i];
        loaded_ = true;
        return true;
    }

    bool set_public_key_hex(const char* hex) noexcept {
        if (hex == nullptr)
            return false;

        std::uint8_t decoded[PUBLIC_KEY_SIZE];
        for (std::size_t i = 0; i < PUBLIC_KEY_SIZE; ++i) {
            const int high = hex_nibble(hex[i * 2]);
            const int low = hex_nibble(hex[i * 2 + 1]);
            if (high < 0 || low < 0) {
                detail::secure_wipe(decoded, sizeof(decoded));
                loaded_ = false;
                return false;
            }
            decoded[i] = static_cast<std::uint8_t>((high << 4) | low);
        }

        const bool ok = set_public_key(decoded, sizeof(decoded));
        detail::secure_wipe(decoded, sizeof(decoded));
        return ok;
    }

    bool loaded() const noexcept { return loaded_; }

    bool verify(const std::uint8_t* message, std::size_t message_length,
                const std::uint8_t* signature,
                std::size_t signature_length) const noexcept {
        if (!loaded_ || signature == nullptr ||
            signature_length != SIGNATURE_SIZE)
            return false;

        if (message == nullptr && message_length != 0)
            return false;

        return crypto_ed25519_check(signature, public_key_,
                                    message, message_length) == 0;
    }

    bool verify_hex(const std::uint8_t* message, std::size_t message_length,
                    const char* signature_hex) const noexcept {
        if (signature_hex == nullptr)
            return false;

        std::uint8_t decoded[SIGNATURE_SIZE];
        for (std::size_t i = 0; i < SIGNATURE_SIZE; ++i) {
            const int high = hex_nibble(signature_hex[i * 2]);
            const int low = hex_nibble(signature_hex[i * 2 + 1]);
            if (high < 0 || low < 0) {
                detail::secure_wipe(decoded, sizeof(decoded));
                return false;
            }
            decoded[i] = static_cast<std::uint8_t>((high << 4) | low);
        }

        const bool ok = verify(message, message_length, decoded, sizeof(decoded));
        detail::secure_wipe(decoded, sizeof(decoded));
        return ok;
    }

    ~Ed25519() noexcept { detail::secure_wipe(public_key_, sizeof(public_key_)); }

    Ed25519() = default;
    Ed25519(const Ed25519&) = delete;
    Ed25519& operator=(const Ed25519&) = delete;

private:
    static int hex_nibble(char c) noexcept {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    std::uint8_t public_key_[PUBLIC_KEY_SIZE]{};
    bool loaded_ = false;
};

}  // namespace veil
