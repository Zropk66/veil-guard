#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"
#include "../detail/mix.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>
#include <intrin.h>

namespace veil::providers {

// 四路物理熵混合。系统 CNG 被改写时仍能产出不可预测的密钥材料。
class Entropy {
public:
    static constexpr std::size_t KEY_SIZE = 32;
    static constexpr std::size_t NONCE_SIZE = 12;

    Entropy() noexcept { reseed(); }

    void reseed() noexcept {
        const std::uint64_t sources[4] = {
            rdtsc(),
            rdrand(),
            query_counter(),
            address_jitter(),
        };

        std::uint8_t seed[KEY_SIZE];
        for (std::size_t i = 0; i < 4; ++i) {
            const std::uint64_t mixed =
                detail::mix64(sources[i] ^ (0x9E3779B97F4A7C15ULL * (i + 1)));
            for (std::size_t b = 0; b < 8; ++b)
                seed[i * 8 + b] = static_cast<std::uint8_t>(mixed >> (b * 8));
        }

        detail::secure_wipe(key_, KEY_SIZE);
        detail::secure_wipe(nonce_, NONCE_SIZE);

        for (std::size_t i = 0; i < KEY_SIZE; ++i)
            key_[i] = seed[i];
        for (std::size_t i = 0; i < NONCE_SIZE; ++i)
            nonce_[i] = seed[(i + 17) % KEY_SIZE] ^ static_cast<std::uint8_t>(i);
        for (std::size_t i = 0; i < 4; ++i)
            counter_[i] = static_cast<std::uint8_t>(seed[i] ^ seed[i + 23]);

        detail::secure_wipe(seed, KEY_SIZE);
    }

    void generate(void* output, std::size_t size) noexcept {
        auto* out = static_cast<std::uint8_t*>(output);
        while (size > 0) {
            std::uint8_t block[64];
            chacha20_block(block);
            increment_counter();

            const std::size_t take = size < 64 ? size : 64;
            for (std::size_t i = 0; i < take; ++i)
                out[i] = block[i];
            detail::secure_wipe(block, 64);

            out += take;
            size -= take;
        }
    }

    // 生成 nonce 并写为十六进制串。容量需大于 2 * NONCE_SIZE。
    //
    // 服务端用同一个 nonce 复现派生，因此它必须是每次请求新生成的。
    // 用系统 CSPRNG 也可，但那条路径依赖被改写的 rand 导出；这里的
    // 四路物理熵不经过任何可挂钩的接口。
    bool nonce_hex(char* out, std::size_t capacity) noexcept {
        constexpr std::size_t HEX = NONCE_SIZE * 2;
        if (out == nullptr || capacity <= HEX)
            return false;

        std::uint8_t raw[NONCE_SIZE];
        generate(raw, sizeof(raw));

        static constexpr char kHex[] = "0123456789abcdef";
        for (std::size_t i = 0; i < NONCE_SIZE; ++i) {
            out[i * 2] = kHex[raw[i] >> 4];
            out[i * 2 + 1] = kHex[raw[i] & 0x0F];
        }
        out[HEX] = '\0';

        detail::secure_wipe(raw, sizeof(raw));
        return true;
    }

    ~Entropy() noexcept {
        detail::secure_wipe(key_, KEY_SIZE);
        detail::secure_wipe(nonce_, NONCE_SIZE);
        detail::secure_wipe(counter_, 4);
    }

    Entropy(const Entropy&) = delete;
    Entropy& operator=(const Entropy&) = delete;

private:
    static std::uint64_t rdtsc() noexcept {
        return __rdtsc();
    }

    // RDRAND 在部分虚拟化环境下被禁用。十六次重试后仍失败时回落到
    // 时间戳混合，而不是返回零值。
    static std::uint64_t rdrand() noexcept {
        std::uint64_t value = 0;
        unsigned char ok = 0;
        for (int attempt = 0; attempt < 16 && ok == 0; ++attempt)
            ok = static_cast<unsigned char>(_rdrand64_step(&value));

        if (ok == 0)
            return detail::mix64(__rdtsc() ^ 0xA5A5A5A5A5A5A5A5ULL);
        return value;
    }

    static std::uint64_t query_counter() noexcept {
        LARGE_INTEGER counter{};
        QueryPerformanceCounter(&counter);
        return static_cast<std::uint64_t>(counter.QuadPart);
    }

    static std::uint64_t address_jitter() noexcept {
        std::uint64_t local = 0;
        void* heap = HeapAlloc(GetProcessHeap(), 0, 32);
        if (heap != nullptr)
            HeapFree(GetProcessHeap(), 0, heap);
        return detail::mix64(reinterpret_cast<std::uintptr_t>(&local) ^
                             reinterpret_cast<std::uintptr_t>(heap));
    }

    static std::uint32_t rotl32(std::uint32_t value, int count) noexcept {
        return (value << count) | (value >> (32 - count));
    }

    static void quarter_round(std::uint32_t& a, std::uint32_t& b,
                              std::uint32_t& c, std::uint32_t& d) noexcept {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    void chacha20_block(std::uint8_t out[64]) const noexcept {
        std::uint32_t state[16] = {
            0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        };

        for (std::size_t i = 0; i < 8; ++i) {
            state[4 + i] = static_cast<std::uint32_t>(key_[i * 4]) |
                           (static_cast<std::uint32_t>(key_[i * 4 + 1]) << 8) |
                           (static_cast<std::uint32_t>(key_[i * 4 + 2]) << 16) |
                           (static_cast<std::uint32_t>(key_[i * 4 + 3]) << 24);
        }

        state[12] = static_cast<std::uint32_t>(counter_[0]) |
                    (static_cast<std::uint32_t>(counter_[1]) << 8) |
                    (static_cast<std::uint32_t>(counter_[2]) << 16) |
                    (static_cast<std::uint32_t>(counter_[3]) << 24);

        for (std::size_t chunk = 0; chunk < 3; ++chunk) {
            state[13 + chunk] =
                static_cast<std::uint32_t>(nonce_[chunk * 4]) |
                (static_cast<std::uint32_t>(nonce_[chunk * 4 + 1]) << 8) |
                (static_cast<std::uint32_t>(nonce_[chunk * 4 + 2]) << 16) |
                (static_cast<std::uint32_t>(nonce_[chunk * 4 + 3]) << 24);
        }

        std::uint32_t working[16];
        for (std::size_t i = 0; i < 16; ++i)
            working[i] = state[i];

        for (int round = 0; round < 10; ++round) {
            quarter_round(working[0], working[4], working[8], working[12]);
            quarter_round(working[1], working[5], working[9], working[13]);
            quarter_round(working[2], working[6], working[10], working[14]);
            quarter_round(working[3], working[7], working[11], working[15]);
            quarter_round(working[0], working[5], working[10], working[15]);
            quarter_round(working[1], working[6], working[11], working[12]);
            quarter_round(working[2], working[7], working[8], working[13]);
            quarter_round(working[3], working[4], working[9], working[14]);
        }

        for (std::size_t i = 0; i < 16; ++i) {
            const std::uint32_t v = working[i] + state[i];
            out[i * 4] = static_cast<std::uint8_t>(v);
            out[i * 4 + 1] = static_cast<std::uint8_t>(v >> 8);
            out[i * 4 + 2] = static_cast<std::uint8_t>(v >> 16);
            out[i * 4 + 3] = static_cast<std::uint8_t>(v >> 24);
        }

        detail::secure_wipe(state, sizeof(state));
        detail::secure_wipe(working, sizeof(working));
    }

    void increment_counter() noexcept {
        for (std::size_t i = 0; i < 4; ++i) {
            if (++counter_[i] != 0)
                break;
        }
    }

    std::uint8_t key_[KEY_SIZE]{};
    std::uint8_t nonce_[NONCE_SIZE]{};
    std::uint8_t counter_[4]{};
};

}  // namespace veil::providers
