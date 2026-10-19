#include <veil/crypto/ed25519.hpp>
#include "support/test_main.hpp"

#include <cstring>

namespace {

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void from_hex(const char* hex, std::uint8_t* out, std::size_t size) {
    for (std::size_t i = 0; i < size; ++i)
        out[i] = static_cast<std::uint8_t>(hex_nibble(hex[i * 2]) << 4 |
                                           hex_nibble(hex[i * 2 + 1]));
}

}  // namespace

int main() {
    using namespace veil;

    // RFC 8032 7.1 TEST 1：空消息
    const char* public_test1 =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char* signature_test1 =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
        "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    Ed25519 verifier;
    test::expect(verifier.set_public_key_hex(public_test1),
                 "ed25519 accepts valid public key hex");
    test::expect(verifier.loaded(), "ed25519 reports loaded after set");
    test::expect(verifier.verify(nullptr, 0, nullptr, 0) == false,
                 "ed25519 rejects null signature");
    test::expect(verifier.verify(reinterpret_cast<const std::uint8_t*>(""), 0,
                                 reinterpret_cast<const std::uint8_t*>(signature_test1), 0)
                     == false,
                 "ed25519 rejects signature with wrong declared length");

    std::uint8_t signature1[64];
    from_hex(signature_test1, signature1, sizeof(signature1));
    test::expect(verifier.verify(nullptr, 0, signature1, sizeof(signature1)),
                 "ed25519 verifies RFC 8032 test 1 with null message pointer");

    // RFC 8032 7.1 TEST 2：单字节消息
    const char* public_test2 =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const char* signature_test2 =
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    const std::uint8_t message_test2[1] = {0x72};

    Ed25519 second;
    test::expect(second.set_public_key_hex(public_test2),
                 "ed25519 accepts second RFC 8032 key");
    std::uint8_t signature2[64];
    from_hex(signature_test2, signature2, sizeof(signature2));
    test::expect(second.verify(message_test2, sizeof(message_test2),
                               signature2, sizeof(signature2)),
                 "ed25519 verifies RFC 8032 test 2");

    // 消息被改一个字节必须失败
    const std::uint8_t altered[1] = {0x73};
    test::expect(!second.verify(altered, sizeof(altered), signature2, sizeof(signature2)),
                 "ed25519 rejects mismatched message");

    // 换用另一把公钥必须失败
    Ed25519 crossed;
    crossed.set_public_key_hex(public_test1);
    test::expect(!crossed.verify(message_test2, sizeof(message_test2),
                                 signature2, sizeof(signature2)),
                 "ed25519 rejects signature under unrelated public key");

    // 签名被改一个字节必须失败
    std::uint8_t corrupted[64];
    std::memcpy(corrupted, signature2, sizeof(corrupted));
    corrupted[0] ^= 0x01;
    test::expect(!second.verify(message_test2, sizeof(message_test2),
                                corrupted, sizeof(corrupted)),
                 "ed25519 rejects corrupted signature");

    // 非法公钥长度必须拒绝且不保留半初始化状态
    Ed25519 strict;
    const std::uint8_t short_key[31]{};
    test::expect(!strict.set_public_key(short_key, 31),
                 "ed25519 rejects short public key");
    test::expect(!strict.loaded(), "ed25519 clears loaded on bad key");
    test::expect(!strict.verify(message_test2, sizeof(message_test2),
                                signature2, sizeof(signature2)),
                 "ed25519 refuses to verify while unloaded");
    test::expect(!strict.set_public_key(nullptr, 32),
                 "ed25519 rejects null public key");

    // 非法十六进制必须拒绝
    Ed25519 hex_strict;
    test::expect(!hex_strict.set_public_key_hex("zz"),
                 "ed25519 rejects non-hex public key");
    test::expect(!hex_strict.set_public_key_hex(nullptr),
                 "ed25519 rejects null hex");
    test::expect(!hex_strict.set_public_key_hex(
                     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511z"),
                 "ed25519 rejects public key hex with trailing junk");
    test::expect(!hex_strict.loaded(),
                 "ed25519 stays unloaded across failed hex parses");

    // 签名长度不符必须拒绝
    std::uint8_t short_sig[63]{};
    test::expect(!second.verify(message_test2, sizeof(message_test2),
                                short_sig, sizeof(short_sig)),
                 "ed25519 rejects short signature");
    test::expect(!second.verify_hex(message_test2, sizeof(message_test2), nullptr),
                 "ed25519 rejects null signature hex");
    test::expect(!second.verify_hex(message_test2, sizeof(message_test2), "00"),
                 "ed25519 rejects truncated signature hex");

    return test::finish("ed25519");
}
