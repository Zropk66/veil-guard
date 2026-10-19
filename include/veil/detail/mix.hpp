#pragma once

#include "../config.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::detail {

VEIL_FORCEINLINE constexpr std::uint64_t mix64(std::uint64_t x) noexcept {
    x ^= x >> 33;
    x *= 0xFF51AFD7ED558CCDULL;
    x ^= x >> 33;
    x *= 0xC4CEB9FE1A85EC53ULL;
    x ^= x >> 33;
    return x;
}

VEIL_FORCEINLINE constexpr std::uint32_t fnv1a32(const char* text, std::uint32_t salt) noexcept {
    std::uint32_t h = 0x811C9DC5u ^ salt;
    while (*text != '\0') {
        h ^= static_cast<std::uint32_t>(static_cast<unsigned char>(*text++));
        h *= 0x01000193u;
    }
    return h;
}

VEIL_FORCEINLINE constexpr std::uint32_t crc32_step(std::uint32_t crc, unsigned char byte) noexcept {
    crc ^= byte;
    for (int bit = 0; bit < 8; ++bit)
        crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    return crc;
}

VEIL_FORCEINLINE std::uint32_t crc32(const void* data, std::size_t size) noexcept {
    const auto* p = static_cast<const unsigned char*>(data);
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < size; ++i)
        crc = crc32_step(crc, p[i]);
    return ~crc;
}

// 以槽位序号派生独立盐，避免不同调用点共享常量。
template <std::uint64_t Slot>
struct Salt {
    static constexpr std::uint64_t value =
        mix64(BUILD_SEED ^ (Slot * 0x2545F4914F6CDD1DULL));
    static constexpr std::uint32_t hash_salt =
        static_cast<std::uint32_t>(value ^ (value >> 32));
};

}  // namespace veil::detail
