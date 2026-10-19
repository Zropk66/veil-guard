#pragma once

#include "sha256.hpp"

#include <cstddef>
#include <cstdint>

namespace veil {

class Hmac {
public:
    static void compute(const void* key, std::size_t key_len,
                        const void* data, std::size_t data_len,
                        std::uint8_t out[Sha256::DIGEST_SIZE]) noexcept {
        std::uint8_t normalized[Sha256::BLOCK_SIZE]{};
        if (key_len > Sha256::BLOCK_SIZE) {
            Sha256::hash(key, key_len, normalized);
        } else if (key_len > 0) {
            const auto* p = static_cast<const std::uint8_t*>(key);
            for (std::size_t i = 0; i < key_len; ++i)
                normalized[i] = p[i];
        }

        std::uint8_t ipad[Sha256::BLOCK_SIZE];
        std::uint8_t opad[Sha256::BLOCK_SIZE];
        for (std::size_t i = 0; i < Sha256::BLOCK_SIZE; ++i) {
            ipad[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x36);
            opad[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x5c);
        }

        std::uint8_t inner[Sha256::DIGEST_SIZE];
        Sha256 ctx;
        ctx.init();
        ctx.update(ipad, Sha256::BLOCK_SIZE);
        ctx.update(data, data_len);
        ctx.final(inner);

        ctx.init();
        ctx.update(opad, Sha256::BLOCK_SIZE);
        ctx.update(inner, Sha256::DIGEST_SIZE);
        ctx.final(out);

        detail::secure_wipe(normalized, sizeof(normalized));
        detail::secure_wipe(ipad, sizeof(ipad));
        detail::secure_wipe(opad, sizeof(opad));
        detail::secure_wipe(inner, sizeof(inner));
    }
};

}  // namespace veil
