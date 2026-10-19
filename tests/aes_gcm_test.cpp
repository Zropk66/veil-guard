#include <veil/crypto/aes_gcm.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    // NIST SP 800-38D 用例 13：全零密钥、全零 IV、空明文
    {
        std::uint8_t key[32]{};
        std::uint8_t nonce[12]{};
        Aes256Gcm gcm;
        gcm.set_key(key);
        std::uint8_t tag[16];
        gcm.encrypt(nonce, nullptr, 0, nullptr, 0, nullptr, tag);
        const std::uint8_t expected[16] = {
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
            0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
        };
        test::expect(detail::constant_time_compare(tag, expected, 16) == 1,
                     "aes-256-gcm matches NIST case 13 tag");
    }

    // NIST SP 800-38D 用例 14：单块全零明文
    {
        std::uint8_t key[32]{};
        std::uint8_t nonce[12]{};
        std::uint8_t plain[16]{};
        std::uint8_t cipher[16];
        std::uint8_t tag[16];
        Aes256Gcm gcm;
        gcm.set_key(key);
        gcm.encrypt(nonce, plain, sizeof(plain), nullptr, 0, cipher, tag);
        const std::uint8_t expected_cipher[16] = {
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
            0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        };
        const std::uint8_t expected_tag[16] = {
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
            0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
        };
        test::expect(detail::constant_time_compare(cipher, expected_cipher, 16) == 1,
                     "aes-256-gcm matches NIST case 14 ciphertext");
        test::expect(detail::constant_time_compare(tag, expected_tag, 16) == 1,
                     "aes-256-gcm matches NIST case 14 tag");
    }

    // 跨块明文：62 字节覆盖多块与末尾非整块两条计数路径
    {
        std::uint8_t key[32];
        std::uint8_t nonce[12];
        for (std::size_t i = 0; i < 32; ++i)
            key[i] = static_cast<std::uint8_t>(i * 7 + 3);
        for (std::size_t i = 0; i < 12; ++i)
            nonce[i] = static_cast<std::uint8_t>(i * 11 + 1);

        const char text[] = "veil evidence binding round trip over multiple cipher blocks";
        std::uint8_t message[sizeof(text)];
        std::memcpy(message, text, sizeof(message));
        std::uint8_t cipher[sizeof(message)];
        std::uint8_t tag[16];
        std::uint8_t plain[sizeof(message)];

        Aes256Gcm gcm;
        gcm.set_key(key);
        test::expect(gcm.encrypt(nonce, message, sizeof(message), nullptr, 0,
                                 cipher, tag), "aes-256-gcm encrypt succeeds");
        test::expect(gcm.decrypt(nonce, cipher, sizeof(message), tag, nullptr, 0,
                                 plain), "aes-256-gcm decrypt succeeds");
        test::expect(std::memcmp(plain, message, sizeof(message)) == 0,
                     "aes-256-gcm round trip preserves plaintext");

        // 标签被篡改时不得产出明文
        std::uint8_t bad_tag[16];
        std::memcpy(bad_tag, tag, 16);
        bad_tag[0] ^= 0x01;
        std::uint8_t untouched[sizeof(message)];
        std::memset(untouched, 0xAA, sizeof(untouched));
        test::expect(!gcm.decrypt(nonce, cipher, sizeof(message), bad_tag, nullptr, 0,
                                  untouched),
                     "aes-256-gcm rejects tampered tag");
        bool untouched_ok = true;
        for (std::size_t i = 0; i < sizeof(untouched); ++i)
            if (untouched[i] != 0xAA)
                untouched_ok = false;
        test::expect(untouched_ok,
                     "aes-256-gcm writes nothing on tag mismatch");

        // 密文自身被篡改时标签必须失配
        std::uint8_t bad_cipher[sizeof(message)];
        std::memcpy(bad_cipher, cipher, sizeof(bad_cipher));
        bad_cipher[sizeof(bad_cipher) - 1] ^= 0x80;
        test::expect(!gcm.decrypt(nonce, bad_cipher, sizeof(message), tag, nullptr, 0,
                                  plain),
                     "aes-256-gcm rejects tampered ciphertext");

        // AAD 参与认证
        std::uint8_t with_aad_tag[16];
        const std::uint8_t aad[] = {0x01, 0x02, 0x03};
        gcm.encrypt(nonce, message, sizeof(message), aad, sizeof(aad), cipher, with_aad_tag);
        test::expect(detail::constant_time_compare(tag, with_aad_tag, 16) == 0,
                     "aes-256-gcm binds aad into tag");

        // nonce 变化必须让密文整体变化
        std::uint8_t other_nonce[12];
        std::memcpy(other_nonce, nonce, sizeof(other_nonce));
        other_nonce[0] ^= 0x40;
        std::uint8_t other_cipher[sizeof(message)];
        std::uint8_t other_tag[16];
        gcm.encrypt(other_nonce, message, sizeof(message), nullptr, 0,
                    other_cipher, other_tag);
        test::expect(std::memcmp(cipher, other_cipher, sizeof(message)) != 0,
                     "aes-256-gcm ciphertext depends on nonce");

        // 未设置密钥时必须显式失败而不是产出零标签
        Aes256Gcm unready;
        std::uint8_t cold_tag[16];
        test::expect(!unready.encrypt(nonce, message, sizeof(message), nullptr, 0,
                                      other_cipher, cold_tag),
                     "aes-256-gcm refuses to encrypt before set_key");
    }

    return test::finish("aes_gcm");
}
