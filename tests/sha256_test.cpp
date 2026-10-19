#include <veil/crypto/sha256.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    std::uint8_t digest[32];

    Sha256::hash("abc", 3, digest);
    const std::uint8_t expected_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    test::expect(detail::constant_time_compare(digest, expected_abc, 32) == 1,
                 "sha256 matches FIPS 180-4 vector for abc");

    Sha256::hash("", 0, digest);
    const std::uint8_t expected_empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    test::expect(detail::constant_time_compare(digest, expected_empty, 32) == 1,
                 "sha256 matches vector for empty input");

    // 跨块边界：64 字节正好一个块，65 字节触发填充分支
    char block[65];
    std::memset(block, 'a', sizeof(block));
    Sha256::hash(block, 64, digest);
    const std::uint8_t first = digest[0];
    Sha256::hash(block, 65, digest);
    test::expect(first != digest[0], "sha256 distinguishes block boundary lengths");

    return test::finish("sha256");
}
