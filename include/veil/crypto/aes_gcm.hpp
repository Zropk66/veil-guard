#pragma once

#include "aes.hpp"

#include <cstddef>
#include <cstdint>

namespace veil {

// AES-256-GCM。标签校验是解密的前置条件：不匹配时不写入任何输出，
// 不存在「先比对再解密」留下的可跳过窗口。
class Aes256Gcm {
public:
    static constexpr std::size_t KEY_SIZE = 32;
    static constexpr std::size_t NONCE_SIZE = 12;
    static constexpr std::size_t TAG_SIZE = 16;

    void set_key(const std::uint8_t key[KEY_SIZE]) noexcept {
        cipher_.set_key(key);
        derive_h();
        ready_ = true;
    }

    bool decrypt(const std::uint8_t* nonce,
                 const std::uint8_t* ciphertext, std::size_t length,
                 const std::uint8_t tag[TAG_SIZE],
                 const std::uint8_t* aad, std::size_t aad_len,
                 std::uint8_t* out) noexcept {
        if (!ready_)
            return false;

        std::uint8_t expected[TAG_SIZE];
        compute_tag(nonce, ciphertext, length, aad, aad_len, expected);

        if (detail::constant_time_compare(expected, tag, TAG_SIZE) == 0) {
            detail::secure_wipe(expected, sizeof(expected));
            return false;
        }
        detail::secure_wipe(expected, sizeof(expected));

        ctr_crypt(nonce, ciphertext, length, out);
        return true;
    }

    bool encrypt(const std::uint8_t* nonce,
                 const std::uint8_t* plaintext, std::size_t length,
                 const std::uint8_t* aad, std::size_t aad_len,
                 std::uint8_t* out, std::uint8_t tag[TAG_SIZE]) noexcept {
        if (!ready_)
            return false;

        ctr_crypt(nonce, plaintext, length, out);
        compute_tag(nonce, out, length, aad, aad_len, tag);
        return true;
    }

private:
    void derive_h() noexcept {
        std::uint8_t zero[16]{};
        std::uint8_t h[16];
        cipher_.encrypt_block(zero, h);
        for (std::size_t i = 0; i < 16; ++i)
            h_[i] = h[i];
        detail::secure_wipe(h, sizeof(h));
    }

    void ctr_crypt(const std::uint8_t* nonce,
                   const std::uint8_t* input, std::size_t length,
                   std::uint8_t* out) noexcept {
        std::uint8_t counter[16]{};
        for (std::size_t i = 0; i < NONCE_SIZE; ++i)
            counter[i] = nonce[i];
        // 96 位 nonce 下 J0 = nonce ‖ 0x00000001，数据加密自 inc32(J0) 起算。
        // 起始值取 1 会与标签掩码的 E_K(J0) 重合，导致密文整体偏移一块。
        counter[15] = 2;

        std::uint8_t keystream[16];
        std::size_t offset = 0;

        while (offset < length) {
            cipher_.encrypt_block(counter, keystream);

            const std::size_t take = (length - offset < 16) ? (length - offset) : 16;
            for (std::size_t i = 0; i < take; ++i)
                out[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ keystream[i]);

            for (int i = 15; i >= 12; --i) {
                if (++counter[i] != 0)
                    break;
            }

            offset += take;
        }

        detail::secure_wipe(counter, sizeof(counter));
        detail::secure_wipe(keystream, sizeof(keystream));
    }

    void compute_tag(const std::uint8_t* nonce,
                     const std::uint8_t* data, std::size_t length,
                     const std::uint8_t* aad, std::size_t aad_len,
                     std::uint8_t tag[TAG_SIZE]) const noexcept {
        std::uint8_t state[16]{};

        if (aad != nullptr && aad_len > 0)
            ghash(state, aad, aad_len);

        if (data != nullptr && length > 0)
            ghash(state, data, length);

        std::uint8_t lengths[16]{};
        const std::uint64_t aad_bits = static_cast<std::uint64_t>(aad_len) * 8;
        const std::uint64_t data_bits = static_cast<std::uint64_t>(length) * 8;
        for (std::size_t i = 0; i < 8; ++i) {
            lengths[i] = static_cast<std::uint8_t>(aad_bits >> ((7 - i) * 8));
            lengths[8 + i] = static_cast<std::uint8_t>(data_bits >> ((7 - i) * 8));
        }
        xor_block(state, lengths);
        multiply_h(state);

        std::uint8_t mask[16];
        std::uint8_t counter[16]{};
        for (std::size_t i = 0; i < NONCE_SIZE; ++i)
            counter[i] = nonce[i];
        counter[15] = 1;
        cipher_.encrypt_block(counter, mask);

        for (std::size_t i = 0; i < TAG_SIZE; ++i)
            tag[i] = static_cast<std::uint8_t>(state[i] ^ mask[i]);

        detail::secure_wipe(state, sizeof(state));
        detail::secure_wipe(lengths, sizeof(lengths));
        detail::secure_wipe(mask, sizeof(mask));
    }

    void ghash(std::uint8_t state[16], const std::uint8_t* data,
               std::size_t length) const noexcept {
        std::size_t offset = 0;
        while (offset < length) {
            const std::size_t take = (length - offset < 16) ? (length - offset) : 16;
            std::uint8_t block[16]{};
            for (std::size_t i = 0; i < take; ++i)
                block[i] = data[offset + i];

            xor_block(state, block);
            multiply_h(state);

            offset += take;
        }
    }

    static void xor_block(std::uint8_t state[16], const std::uint8_t block[16]) noexcept {
        for (std::size_t i = 0; i < 16; ++i)
            state[i] ^= block[i];
    }

    void multiply_h(std::uint8_t state[16]) const noexcept {
        std::uint8_t z[16]{};
        std::uint8_t v[16];
        for (std::size_t i = 0; i < 16; ++i)
            v[i] = h_[i];

        for (std::size_t i = 0; i < 128; ++i) {
            const std::size_t byte_index = i / 8;
            const std::size_t bit_index = 7 - (i % 8);
            if ((state[byte_index] >> bit_index) & 1) {
                for (std::size_t k = 0; k < 16; ++k)
                    z[k] ^= v[k];
            }

            const bool lsb = (v[15] & 1) != 0;
            for (int k = 15; k > 0; --k)
                v[k] = static_cast<std::uint8_t>((v[k] >> 1) | ((v[k - 1] & 1) << 7));
            v[0] = static_cast<std::uint8_t>(v[0] >> 1);
            if (lsb)
                v[0] ^= 0xE1;
        }

        for (std::size_t i = 0; i < 16; ++i)
            state[i] = z[i];
    }

    Aes256 cipher_;
    std::uint8_t h_[16]{};
    bool ready_ = false;
};

}  // namespace veil
