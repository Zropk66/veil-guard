#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

namespace veil {

// AES-256 块加密。S 盒由 GF(2^8) 逆元现算，二进制中不留 256 字节常量表。
class Aes256 {
public:
    static constexpr std::size_t BLOCK_SIZE = 16;
    static constexpr std::size_t KEY_SIZE = 32;
    static constexpr std::size_t ROUNDS = 14;

    void set_key(const std::uint8_t key[KEY_SIZE]) noexcept {
        expand_key(key);
        ready_ = true;
    }

    void encrypt_block(const std::uint8_t in[BLOCK_SIZE],
                       std::uint8_t out[BLOCK_SIZE]) const noexcept {
        std::uint8_t state[BLOCK_SIZE];
        for (std::size_t i = 0; i < BLOCK_SIZE; ++i)
            state[i] = static_cast<std::uint8_t>(in[i] ^ round_keys_[i]);

        for (std::size_t round = 1; round < ROUNDS; ++round) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }

        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, ROUNDS);

        for (std::size_t i = 0; i < BLOCK_SIZE; ++i)
            out[i] = state[i];

        detail::secure_wipe(state, sizeof(state));
    }

private:
    static constexpr std::uint8_t gmul(std::uint8_t a, std::uint8_t b) noexcept {
        std::uint8_t result = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1)
                result ^= a;
            const std::uint8_t high = static_cast<std::uint8_t>(a & 0x80);
            a = static_cast<std::uint8_t>(a << 1);
            if (high)
                a ^= 0x1B;
            b = static_cast<std::uint8_t>(b >> 1);
        }
        return result;
    }

    static constexpr std::uint8_t inverse(std::uint8_t x) noexcept {
        if (x == 0)
            return 0;
        // 费马小定理：a^254 是 GF(2^8) 下的乘法逆元
        std::uint8_t result = 1;
        std::uint8_t base = x;
        unsigned int exp = 254;
        while (exp > 0) {
            if (exp & 1)
                result = gmul(result, base);
            base = gmul(base, base);
            exp >>= 1;
        }
        return result;
    }

    static constexpr std::uint8_t sbox(std::uint8_t x) noexcept {
        std::uint8_t inv = inverse(x);
        std::uint8_t y = inv;
        for (int i = 0; i < 4; ++i) {
            inv = static_cast<std::uint8_t>(((inv << 1) | (inv >> 7)) & 0xFF);
            y ^= inv;
        }
        return static_cast<std::uint8_t>(y ^ 0x63);
    }

    void expand_key(const std::uint8_t key[KEY_SIZE]) noexcept {
        constexpr std::size_t words = 4 * (ROUNDS + 1);

        std::uint8_t w[words * 4];
        for (std::size_t i = 0; i < KEY_SIZE; ++i)
            w[i] = key[i];

        std::uint8_t rcon = 0x01;
        for (std::size_t i = KEY_SIZE; i < words * 4; i += 4) {
            std::uint8_t temp[4] = {w[i - 4], w[i - 3], w[i - 2], w[i - 1]};

            if ((i / 4) % 8 == 0) {
                const std::uint8_t first = temp[0];
                temp[0] = static_cast<std::uint8_t>(sbox(temp[1]) ^ rcon);
                temp[1] = sbox(temp[2]);
                temp[2] = sbox(temp[3]);
                temp[3] = sbox(first);
                rcon = static_cast<std::uint8_t>(((rcon << 1) | (rcon >> 7)) & 0xFF);
                if (rcon == 0x1B)
                    rcon = 0x01;
            } else if ((i / 4) % 8 == 4) {
                for (std::size_t k = 0; k < 4; ++k)
                    temp[k] = sbox(temp[k]);
            }

            for (std::size_t k = 0; k < 4; ++k)
                w[i + k] = static_cast<std::uint8_t>(w[i - KEY_SIZE + k] ^ temp[k]);
        }

        for (std::size_t i = 0; i < BLOCK_SIZE; ++i)
            for (std::size_t k = 0; k < ROUNDS + 1; ++k)
                round_keys_[k * BLOCK_SIZE + i] = w[k * 16 + i];

        detail::secure_wipe(w, sizeof(w));
    }

    static void sub_bytes(std::uint8_t state[BLOCK_SIZE]) noexcept {
        for (std::size_t i = 0; i < BLOCK_SIZE; ++i)
            state[i] = sbox(state[i]);
    }

    static void shift_rows(std::uint8_t state[BLOCK_SIZE]) noexcept {
        std::uint8_t temp[BLOCK_SIZE];
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                temp[c * 4 + r] = state[((c + r) % 4) * 4 + r];
        for (std::size_t i = 0; i < BLOCK_SIZE; ++i)
            state[i] = temp[i];
    }

    static void mix_columns(std::uint8_t state[BLOCK_SIZE]) noexcept {
        for (std::size_t c = 0; c < 4; ++c) {
            std::uint8_t* col = &state[c * 4];
            const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
            col[0] = static_cast<std::uint8_t>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
            col[1] = static_cast<std::uint8_t>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
            col[2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
            col[3] = static_cast<std::uint8_t>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
        }
    }

    void add_round_key(std::uint8_t state[BLOCK_SIZE], std::size_t round) const noexcept {
        for (std::size_t i = 0; i < BLOCK_SIZE; ++i)
            state[i] ^= round_keys_[round * BLOCK_SIZE + i];
    }

    std::uint8_t round_keys_[(ROUNDS + 1) * BLOCK_SIZE]{};
    bool ready_ = false;
};

}  // namespace veil
