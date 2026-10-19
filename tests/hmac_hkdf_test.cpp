#include <veil/crypto/hkdf.hpp>
#include <veil/crypto/hmac.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    // RFC 4231 Test Case 2
    const char key[] = "Jefe";
    const char data[] = "what do ya want for nothing?";
    std::uint8_t mac[32];
    Hmac::compute(key, 4, data, std::strlen(data), mac);
    const std::uint8_t expected[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    test::expect(detail::constant_time_compare(mac, expected, 32) == 1,
                 "hmac-sha256 matches RFC 4231 case 2");

    // RFC 5869 Test Case 1
    std::uint8_t ikm[22];
    std::memset(ikm, 0x0b, sizeof(ikm));
    std::uint8_t salt[13];
    for (std::size_t i = 0; i < sizeof(salt); ++i)
        salt[i] = static_cast<std::uint8_t>(i);
    std::uint8_t info[10];
    for (std::size_t i = 0; i < sizeof(info); ++i)
        info[i] = static_cast<std::uint8_t>(0xf0 + i);

    std::uint8_t okm[42];
    hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info),
                okm, sizeof(okm));
    const std::uint8_t expected_okm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };
    test::expect(detail::constant_time_compare(okm, expected_okm, 42) == 1,
                 "hkdf-sha256 matches RFC 5869 case 1");

    // 空盐必须与显式盐产生不同输出，否则盐绑定失效
    std::uint8_t with_salt[32];
    std::uint8_t without_salt[32];
    hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt), nullptr, 0,
                with_salt, sizeof(with_salt));
    hkdf_sha256(ikm, sizeof(ikm), nullptr, 0, nullptr, 0,
                without_salt, sizeof(without_salt));
    test::expect(detail::constant_time_compare(with_salt, without_salt, 32) == 0,
                 "hkdf binds to salt");

    // 近阈值长度必须仍然确定，且长度不同必须产生不同输出
    std::uint8_t under[991];
    std::uint8_t over[992];
    std::memset(under, 0x5a, sizeof(under));
    std::memset(over, 0x5a, sizeof(over));
    std::uint8_t a[32];
    std::uint8_t b[32];
    std::uint8_t c[32];
    hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt), under, sizeof(under), a, sizeof(a));
    hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt), under, sizeof(under), b, sizeof(b));
    hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt), over, sizeof(over), c, sizeof(c));
    test::expect(detail::constant_time_compare(a, b, 32) == 1,
                 "hkdf is deterministic across repeated calls");
    test::expect(detail::constant_time_compare(a, c, 32) == 0,
                 "hkdf distinguishes inputs differing by one byte");

    return test::finish("hmac_hkdf");
}
