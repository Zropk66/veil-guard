#include <veil/detail/common.hpp>
#include <veil/license/signed_envelope.hpp>
#include "support/test_main.hpp"

#include <cstring>

extern "C" {
void crypto_ed25519_key_pair(uint8_t secret_key[64], uint8_t public_key[32],
                             uint8_t seed[32]);
void crypto_ed25519_sign(uint8_t signature[64], const uint8_t secret_key[64],
                         const uint8_t* message, size_t message_size);
}

namespace {

using namespace veil;

// 测试侧的服务端。仅用于生成合法信封，与库内代码不共享任何状态。
class Server {
public:
    explicit Server(std::uint8_t seed_byte = 3) noexcept {
        std::uint8_t seed[32];
        for (std::size_t i = 0; i < sizeof(seed); ++i)
            seed[i] = static_cast<std::uint8_t>(i * 7 + seed_byte);
        crypto_ed25519_key_pair(secret_key_, public_key_, seed);
    }

    const std::uint8_t* public_key() const noexcept { return public_key_; }

    bool public_key_hex(char* out, std::size_t capacity) const noexcept {
        if (capacity < 65)
            return false;
        for (std::size_t i = 0; i < 32; ++i) {
            const std::uint8_t byte = public_key_[i];
            out[i * 2] = static_cast<char>("0123456789abcdef"[byte >> 4]);
            out[i * 2 + 1] = static_cast<char>("0123456789abcdef"[byte & 0x0F]);
        }
        out[64] = '\0';
        return true;
    }

    // 构造一份信封：先加密，再对信封全部字节签名
    std::size_t seal(const void* card_key, std::size_t card_key_len,
                     const void* evidence, std::size_t evidence_len,
                     std::uint8_t domain, std::uint64_t issued_at,
                     const std::uint8_t* nonce,
                     const void* plaintext, std::size_t plaintext_len,
                     std::uint8_t* cipher, std::uint8_t* tag,
                     std::uint8_t* signature) const noexcept {
        if (plaintext_len == 0 ||
            plaintext_len > license::SignedEnvelope::MAX_PLAINTEXT)
            return 0;

        std::uint8_t session_key[evidence::Binder::KEY_SIZE];
        if (!evidence::Binder::derive(card_key, card_key_len, nonce,
                                      license::SignedEnvelope::NONCE_SIZE,
                                      evidence, evidence_len, domain,
                                      session_key))
            return 0;

        std::uint8_t aad[license::SignedEnvelope::STAMP_SIZE +
                         license::SignedEnvelope::NONCE_SIZE + 1];
        std::size_t aad_len = 0;
        detail::store_le64(aad, issued_at);
        aad_len += license::SignedEnvelope::STAMP_SIZE;
        for (std::size_t i = 0; i < license::SignedEnvelope::NONCE_SIZE; ++i)
            aad[aad_len++] = nonce[i];
        aad[aad_len++] = domain;

        Aes256Gcm cipher_impl;
        cipher_impl.set_key(session_key);
        const bool encrypted =
            cipher_impl.encrypt(nonce,
                                static_cast<const std::uint8_t*>(plaintext),
                                plaintext_len, aad, aad_len, cipher, tag);

        detail::secure_wipe(session_key, sizeof(session_key));
        detail::secure_wipe(aad, sizeof(aad));
        if (!encrypted)
            return 0;

        std::uint8_t message[license::SignedEnvelope::MAX_SIGNED_MESSAGE];
        std::size_t message_len = 0;
        detail::store_le64(message, issued_at);
        message_len += license::SignedEnvelope::STAMP_SIZE;
        for (std::size_t i = 0; i < license::SignedEnvelope::NONCE_SIZE; ++i)
            message[message_len++] = nonce[i];
        for (std::size_t i = 0; i < plaintext_len; ++i)
            message[message_len++] = cipher[i];
        for (std::size_t i = 0; i < license::SignedEnvelope::TAG_SIZE; ++i)
            message[message_len++] = tag[i];

        crypto_ed25519_sign(signature, secret_key_, message, message_len);
        detail::secure_wipe(message, message_len);
        return plaintext_len;
    }

private:
    std::uint8_t secret_key_[64]{};
    std::uint8_t public_key_[32]{};
};

struct Fixture {
    static constexpr std::size_t PAYLOAD = 32;
    static constexpr std::size_t NONCE = license::SignedEnvelope::NONCE_SIZE;
    static constexpr std::size_t TAG = license::SignedEnvelope::TAG_SIZE;
    static constexpr std::size_t SIG = license::SignedEnvelope::SIGNATURE_SIZE;

    Server server{};
    char public_hex[65]{};
    const char* card_key = "VEIL-ENVELOPE-CARD";
    std::uint8_t nonce[NONCE]{};
    std::uint8_t plaintext[PAYLOAD]{};
    std::uint8_t cipher[PAYLOAD]{};
    std::uint8_t tag[TAG]{};
    std::uint8_t signature[SIG]{};
    std::uint8_t evidence[64]{};
    std::uint64_t issued_at = 1700000000000ULL;

    Fixture() {
        server.public_key_hex(public_hex, sizeof(public_hex));
        for (std::size_t i = 0; i < NONCE; ++i)
            nonce[i] = static_cast<std::uint8_t>(i * 3 + 1);
        for (std::size_t i = 0; i < PAYLOAD; ++i)
            plaintext[i] = static_cast<std::uint8_t>(i + 0x40);
        seal();
    }

    void seal() {
        server.seal(card_key, std::strlen(card_key), evidence,
                    sizeof(evidence), 0x01, issued_at, nonce, plaintext,
                    PAYLOAD, cipher, tag, signature);
    }

    license::SignedEnvelope::Wire wire() const noexcept {
        return license::SignedEnvelope::Wire{issued_at, nonce, cipher,
                                             PAYLOAD, tag, signature};
    }
};

}  // namespace

int main() {
    using namespace veil;

    Fixture fixture;
    test::expect(fixture.server.public_key_hex(fixture.public_hex,
                                               sizeof(fixture.public_hex)),
                 "server exposes a public key");

    license::SignedEnvelope envelope;
    test::expect(envelope.set_verifier_key_hex(fixture.public_hex),
                 "verifier accepts the server public key");
    test::expect(envelope.verifier_loaded(), "verifier reports loaded");

    // 正常解封
    {
        std::uint8_t out[Fixture::PAYLOAD];
        std::memset(out, 0xAA, sizeof(out));

        const std::size_t size = envelope.open(
            fixture.wire(), fixture.card_key, std::strlen(fixture.card_key),
            fixture.evidence, sizeof(fixture.evidence), 0x01,
            fixture.issued_at, 0, out, sizeof(out));

        test::expect(size == Fixture::PAYLOAD, "opens a valid envelope");
        test::expect(std::memcmp(out, fixture.plaintext, Fixture::PAYLOAD) == 0,
                     "recovered plaintext matches");
    }

    // 签名被篡改
    {
        Fixture altered;
        for (std::size_t i = 0; i < Fixture::SIG; ++i)
            altered.signature[i] = 0;
        altered.signature[0] ^= 0x01;

        std::uint8_t out[Fixture::PAYLOAD];
        std::memset(out, 0xAA, sizeof(out));
        const std::size_t size = envelope.open(
            altered.wire(), altered.card_key, std::strlen(altered.card_key),
            altered.evidence, sizeof(altered.evidence), 0x01,
            altered.issued_at, 0, out, sizeof(out));

        test::expect(size == 0, "rejects a tampered signature");
        bool untouched = true;
        for (std::size_t i = 0; i < sizeof(out); ++i)
            if (out[i] != 0xAA)
                untouched = false;
        test::expect(untouched, "rejected envelope writes nothing");
    }

    // 密文被篡改
    {
        Fixture altered;
        altered.cipher[0] ^= 0x01;
        // 只改密文而不重签，签名必然失配
        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            altered.wire(), altered.card_key, std::strlen(altered.card_key),
            altered.evidence, sizeof(altered.evidence), 0x01,
            altered.issued_at, 0, out, sizeof(out));
        test::expect(size == 0, "rejects a tampered ciphertext");
    }

    // 标签被篡改
    {
        Fixture altered;
        altered.tag[0] ^= 0x80;
        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            altered.wire(), altered.card_key, std::strlen(altered.card_key),
            altered.evidence, sizeof(altered.evidence), 0x01,
            altered.issued_at, 0, out, sizeof(out));
        test::expect(size == 0, "rejects a tampered tag");
    }

    // 时间戳被篡改
    {
        Fixture altered;
        altered.issued_at += 1;
        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            altered.wire(), altered.card_key, std::strlen(altered.card_key),
            altered.evidence, sizeof(altered.evidence), 0x01,
            altered.issued_at, 0, out, sizeof(out));
        test::expect(size == 0, "rejects a tampered timestamp");
    }

    // nonce 被篡改
    {
        Fixture altered;
        altered.nonce[0] ^= 0x40;
        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            altered.wire(), altered.card_key, std::strlen(altered.card_key),
            altered.evidence, sizeof(altered.evidence), 0x01,
            altered.issued_at, 0, out, sizeof(out));
        test::expect(size == 0, "rejects a tampered nonce");
    }

    // 错误的服务端密钥
    {
        license::SignedEnvelope other;
        Server stranger(200);
        char stranger_hex[65];
        stranger.public_key_hex(stranger_hex, sizeof(stranger_hex));
        test::expect(other.set_verifier_key_hex(stranger_hex),
                     "loads an unrelated public key");
        test::expect(std::memcmp(stranger_hex, fixture.public_hex, 64) != 0,
                     "the unrelated key differs from the signing key");

        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = other.open(
            fixture.wire(), fixture.card_key, std::strlen(fixture.card_key),
            fixture.evidence, sizeof(fixture.evidence), 0x01,
            fixture.issued_at, 0, out, sizeof(out));
        test::expect(size == 0, "rejects an envelope signed by another key");
    }

    // 卡密不符：签名仍然有效，但派生出的密钥不同，标签校验失败
    {
        const char other_card[] = "VEIL-ENVELOPE-OTHER";
        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            fixture.wire(), other_card, std::strlen(other_card),
            fixture.evidence, sizeof(fixture.evidence), 0x01,
            fixture.issued_at, 0, out, sizeof(out));
        test::expect(size == 0, "rejects a mismatched card key");
    }

    // 证据不符：模拟环境被篡改
    {
        std::uint8_t tampered_evidence[64];
        std::memcpy(tampered_evidence, fixture.evidence,
                    sizeof(tampered_evidence));
        tampered_evidence[0] = 0x5A;

        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            fixture.wire(), fixture.card_key, std::strlen(fixture.card_key),
            tampered_evidence, sizeof(tampered_evidence), 0x01,
            fixture.issued_at, 0, out, sizeof(out));
        test::expect(size == 0,
                     "rejects evidence deviating from the baseline");
    }

    // 域不符
    {
        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            fixture.wire(), fixture.card_key, std::strlen(fixture.card_key),
            fixture.evidence, sizeof(fixture.evidence), 0x02,
            fixture.issued_at, 0, out, sizeof(out));
        test::expect(size == 0, "rejects a mismatched domain");
    }

    // 年龄检查
    {
        std::uint8_t out[Fixture::PAYLOAD];

        test::expect(envelope.open(fixture.wire(), fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 60000,
                                   out, sizeof(out)) == Fixture::PAYLOAD,
                     "accepts an envelope issued just now");

        test::expect(envelope.open(fixture.wire(), fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at + 59000, 60000,
                                   out, sizeof(out)) == Fixture::PAYLOAD,
                     "accepts an envelope within the age window");

        test::expect(envelope.open(fixture.wire(), fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at + 61000, 60000,
                                   out, sizeof(out)) == 0,
                     "rejects an envelope past the age window");

        // 时钟早于签发时间一律拒绝
        test::expect(envelope.open(fixture.wire(), fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at - 1, 60000,
                                   out, sizeof(out)) == 0,
                     "rejects an envelope issued in the future");
    }

    // 输入校验
    {
        std::uint8_t out[Fixture::PAYLOAD];
        auto wire = fixture.wire();

        test::expect(envelope.open(wire, fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, nullptr,
                                   sizeof(out)) == 0,
                     "null output is rejected");

        test::expect(envelope.open(wire, fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, out, 8) == 0,
                     "undersized output is rejected");

        auto no_nonce = wire;
        no_nonce.nonce = nullptr;
        test::expect(envelope.open(no_nonce, fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "null nonce is rejected");

        auto no_sig = wire;
        no_sig.signature = nullptr;
        test::expect(envelope.open(no_sig, fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "null signature is rejected");

        auto no_tag = wire;
        no_tag.tag = nullptr;
        test::expect(envelope.open(no_tag, fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "null tag is rejected");

        auto no_cipher = wire;
        no_cipher.cipher = nullptr;
        test::expect(envelope.open(no_cipher, fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "null cipher is rejected");

        auto toobig = wire;
        toobig.cipher_length = license::SignedEnvelope::MAX_PLAINTEXT + 1;
        test::expect(envelope.open(toobig, fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "oversized cipher is rejected");
    }

    // 未配置验签公钥时必须拒绝
    {
        license::SignedEnvelope unloaded;
        std::uint8_t out[Fixture::PAYLOAD];
        test::expect(unloaded.open(fixture.wire(), fixture.card_key,
                                   std::strlen(fixture.card_key),
                                   fixture.evidence, sizeof(fixture.evidence),
                                   0x01, fixture.issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "unloaded verifier refuses to open");
        test::expect(!unloaded.set_verifier_key_hex("zz"),
                     "invalid public key hex is rejected");
        test::expect(!unloaded.verifier_loaded(),
                     "failed key load leaves the verifier unloaded");
    }

    // 空证据同样可用：未启用任何 provider 的场景
    {
        std::uint8_t out[Fixture::PAYLOAD];
        const std::size_t size = envelope.open(
            fixture.wire(), fixture.card_key, std::strlen(fixture.card_key),
            nullptr, 0, 0x01, fixture.issued_at, 0, out, sizeof(out));
        test::expect(size == 0,
                     "empty evidence derives a different key and fails");
    }

    return test::finish("signed_envelope");
}
