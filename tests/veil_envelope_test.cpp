#include <veil/detail/common.hpp>
#include <veil/license/signed_envelope.hpp>
#include "support/test_main.hpp"

#include <cstring>
#include <fstream>
#include <string>

namespace {

std::string read_all(const char* path) {
    std::ifstream in(path);
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string field(const std::string& json, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    const std::size_t at = json.find(needle);
    if (at == std::string::npos)
        return {};

    std::size_t cursor = json.find(':', at);
    if (cursor == std::string::npos)
        return {};
    ++cursor;
    while (cursor < json.size() &&
           (json[cursor] == ' ' || json[cursor] == '\n' ||
            json[cursor] == '\r' || json[cursor] == '\t'))
        ++cursor;

    if (cursor >= json.size())
        return {};

    if (json[cursor] == '"') {
        ++cursor;
        std::string out;
        while (cursor < json.size() && json[cursor] != '"')
            out.push_back(json[cursor++]);
        return out;
    }

    std::string out;
    while (cursor < json.size() && json[cursor] != ',' &&
           json[cursor] != '\n' && json[cursor] != '}')
        out.push_back(json[cursor++]);
    return out;
}

std::size_t hex_to_bytes(const std::string& hex, std::uint8_t* out,
                         std::size_t capacity) {
    const std::size_t bytes = hex.size() / 2;
    if (bytes > capacity)
        return 0;
    for (std::size_t i = 0; i < bytes; ++i) {
        const int high = hex_nibble(hex[i * 2]);
        const int low = hex_nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0)
            return 0;
        out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return bytes;
}

}  // namespace

int main() {
    using namespace veil;

    const std::string raw = read_all("tests/fixtures/veil_envelope.json");
    test::expect(!raw.empty(), "loads the server signed envelope fixture");
    if (raw.empty())
        return test::finish("veil_envelope");

    const std::string card = field(raw, "cardKey");
    const std::string hwid = field(raw, "hwid");
    const std::string public_hex = field(raw, "publicKeyHex");
    const std::string issued_text = field(raw, "issuedAt");
    const std::string domain_text = field(raw, "domain");

    std::uint8_t evidence[1024];
    std::uint8_t nonce[license::SignedEnvelope::NONCE_SIZE];
    std::uint8_t cipher[license::SignedEnvelope::MAX_PLAINTEXT];
    std::uint8_t tag[license::SignedEnvelope::TAG_SIZE];
    std::uint8_t signature[license::SignedEnvelope::SIGNATURE_SIZE];
    std::uint8_t expected[license::SignedEnvelope::MAX_PLAINTEXT];

    const std::size_t evidence_len = hex_to_bytes(field(raw, "evidenceHex"),
                                                  evidence, sizeof(evidence));
    const std::size_t nonce_len = hex_to_bytes(field(raw, "nonceHex"),
                                               nonce, sizeof(nonce));
    const std::size_t cipher_len = hex_to_bytes(field(raw, "cipherHex"),
                                                cipher, sizeof(cipher));
    const std::size_t tag_len = hex_to_bytes(field(raw, "tagHex"),
                                             tag, sizeof(tag));
    const std::size_t signature_len = hex_to_bytes(field(raw, "signatureHex"),
                                                   signature, sizeof(signature));
    const std::size_t expected_len = hex_to_bytes(field(raw, "plaintextHex"),
                                                  expected, sizeof(expected));

    test::expect(nonce_len == license::SignedEnvelope::NONCE_SIZE,
                 "fixture nonce is 12 bytes");
    test::expect(tag_len == license::SignedEnvelope::TAG_SIZE,
                 "fixture tag is 16 bytes");
    test::expect(signature_len == license::SignedEnvelope::SIGNATURE_SIZE,
                 "fixture signature is 64 bytes");
    test::expect(cipher_len == 24, "fixture ciphertext is 24 bytes");
    test::expect(expected_len == 24, "fixture plaintext is 24 bytes");

    const auto issued_at = static_cast<std::uint64_t>(
        std::strtoull(issued_text.c_str(), nullptr, 10));
    const auto domain = static_cast<std::uint8_t>(
        std::strtoul(domain_text.c_str(), nullptr, 10));

    license::SignedEnvelope envelope;
    test::expect(envelope.set_verifier_key_hex(public_hex.c_str()),
                 "loads the server public key from the fixture");

    const license::SignedEnvelope::Wire wire{
        issued_at, nonce, cipher, cipher_len, tag, signature};

    const license::SignedEnvelope::Inputs inputs{
        card.data(), card.size(),
        hwid.empty() ? nullptr : hwid.data(), hwid.size(),
        evidence_len == 0 ? nullptr : evidence, evidence_len,
        domain};

    // 核心断言：服务端签发的信封必须能被客户端解开
    {
        std::uint8_t out[license::SignedEnvelope::MAX_PLAINTEXT];
        const std::size_t size = envelope.open(wire, inputs, issued_at, 0, out,
                                               sizeof(out));

        test::expect(size == expected_len,
                     "client opens the server signed envelope");
        test::expect(size == expected_len &&
                         std::memcmp(out, expected, expected_len) == 0,
                     "recovered plaintext matches the server payload");
    }

    // 解出的载荷必须是 24 字节的授权结构，字段值与夹具一致
    if (expected_len == 24) {
        std::uint8_t out[license::SignedEnvelope::MAX_PLAINTEXT];
        envelope.open(wire, inputs, issued_at, 0, out, sizeof(out));

        std::uint64_t issued_field = 0;
        std::uint64_t expires_field = 0;
        std::uint32_t features = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            issued_field |= static_cast<std::uint64_t>(out[i]) << (i * 8);
            expires_field |= static_cast<std::uint64_t>(out[8 + i]) << (i * 8);
        }
        for (std::size_t i = 0; i < 4; ++i)
            features |= static_cast<std::uint32_t>(out[16 + i]) << (i * 8);

        test::expect(issued_field == 1730000000000ULL,
                     "payload issued_at decodes correctly");
        test::expect(expires_field == 1760000000000ULL,
                     "payload expires_at decodes correctly");
        test::expect(features == 0x0000000Fu,
                     "payload feature mask decodes correctly");
    }

    // 换 HWID 必须失败：服务端按签发时的 HWID 派生
    {
        const char wrong_hwid[] = "MACHINE-FIXTURE-2";
        auto altered = inputs;
        altered.hwid = wrong_hwid;
        altered.hwid_len = sizeof(wrong_hwid) - 1;

        std::uint8_t out[license::SignedEnvelope::MAX_PLAINTEXT];
        test::expect(envelope.open(wire, altered, issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "client rejects the envelope under a different hwid");
    }

    // 换卡密必须失败
    {
        const char wrong_card[] = "VEIL-CARD-OTHER";
        auto altered = inputs;
        altered.card_key = wrong_card;
        altered.card_key_len = sizeof(wrong_card) - 1;

        std::uint8_t out[license::SignedEnvelope::MAX_PLAINTEXT];
        test::expect(envelope.open(wire, altered, issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "client rejects the envelope under a different card key");
    }

    // 证据不符必须失败
    {
        std::uint8_t tampered[1024];
        std::memcpy(tampered, evidence, evidence_len);
        tampered[0] ^= 0x01;

        auto altered = inputs;
        altered.evidence = tampered;
        altered.evidence_len = evidence_len;

        std::uint8_t out[license::SignedEnvelope::MAX_PLAINTEXT];
        test::expect(envelope.open(wire, altered, issued_at, 0, out,
                                   sizeof(out)) == 0,
                     "client rejects the envelope under altered evidence");
    }

    // 年龄窗口：夹具签发于 2024 年，按当前时刻必须被拒绝
    {
        std::uint8_t out[license::SignedEnvelope::MAX_PLAINTEXT];
        test::expect(envelope.open(wire, inputs, 1730000000000ULL + 120000,
                                   60000, out, sizeof(out)) == 0,
                     "client rejects an envelope past the age window");

        test::expect(envelope.open(wire, inputs, issued_at, 60000, out,
                                   sizeof(out)) == expected_len,
                     "client accepts the envelope at its issue time");
    }

    return test::finish("veil_envelope");
}
