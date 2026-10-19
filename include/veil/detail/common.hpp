#pragma once

#include "../config.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::detail {

// volatile 写入阻止编译器把擦除优化掉。
VEIL_NOINLINE inline void secure_wipe(void* buffer, std::size_t size) noexcept {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(buffer);
    while (size-- > 0)
        *p++ = 0;
}

// 返回 1 表示相等。调用方不得把结果直接当作分支条件使用。
VEIL_FORCEINLINE int constant_time_compare(const void* a, const void* b,
                                           std::size_t size) noexcept {
    const auto* pa = static_cast<const unsigned char*>(a);
    const auto* pb = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (std::size_t i = 0; i < size; ++i)
        diff |= static_cast<unsigned char>(pa[i] ^ pb[i]);
    return diff == 0 ? 1 : 0;
}

VEIL_FORCEINLINE void store_le64(std::uint8_t* out, std::uint64_t value) noexcept {
    for (std::size_t i = 0; i < 8; ++i)
        out[i] = static_cast<std::uint8_t>(value >> (i * 8));
}

VEIL_FORCEINLINE void store_le32(std::uint8_t* out, std::uint32_t value) noexcept {
    for (std::size_t i = 0; i < 4; ++i)
        out[i] = static_cast<std::uint8_t>(value >> (i * 8));
}

}  // namespace veil::detail
