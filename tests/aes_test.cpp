#include <veil/crypto/aes.hpp>
#include "support/test_main.hpp"

int main() {
    using namespace veil;

    // FIPS-197 附录 C.3：AES-256 单块向量
    const std::uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const std::uint8_t plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const std::uint8_t expected[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };

    Aes256 cipher;
    cipher.set_key(key);

    std::uint8_t out[16];
    cipher.encrypt_block(plain, out);
    test::expect(detail::constant_time_compare(out, expected, 16) == 1,
                 "aes-256 matches FIPS-197 appendix C.3");

    std::uint8_t again[16];
    cipher.encrypt_block(plain, again);
    test::expect(detail::constant_time_compare(out, again, 16) == 1,
                 "aes-256 block encryption is deterministic");

    std::uint8_t other[16];
    std::uint8_t flipped[16];
    for (std::size_t i = 0; i < 16; ++i)
        flipped[i] = plain[i];
    flipped[0] ^= 0x01;
    cipher.encrypt_block(flipped, other);
    test::expect(detail::constant_time_compare(out, other, 16) == 0,
                 "aes-256 avalanches on single bit change");

    // 全零密钥的密钥扩展走独立的轮常量路径
    const std::uint8_t zero_key[32]{};
    Aes256 zero_key_cipher;
    zero_key_cipher.set_key(zero_key);
    const std::uint8_t zero_plain[16]{};
    std::uint8_t zero_out[16];
    zero_key_cipher.encrypt_block(zero_plain, zero_out);
    const std::uint8_t expected_zero[16] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
    };
    test::expect(detail::constant_time_compare(zero_out, expected_zero, 16) == 1,
                 "aes-256 matches FIPS-197 appendix C.3 all zero key");

    return test::finish("aes");
}
