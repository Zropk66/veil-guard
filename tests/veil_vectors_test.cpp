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

// 取 JSON 字符串字段的原始内容，认识反斜杠转义
std::string field(const std::string& json, const char* key,
                  std::size_t from = 0) {
    const std::string needle = std::string("\"") + key + "\"";
    std::size_t at = json.find(needle, from);
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
        while (cursor < json.size()) {
            const char c = json[cursor];
            if (c == '\\') {
                const char next = json[cursor + 1];
                if (next == '"' || next == '\\' || next == '/') {
                    out.push_back(next);
                    cursor += 2;
                    continue;
                }
                if (next == 'n') { out.push_back('\n'); cursor += 2; continue; }
                if (next == 't') { out.push_back('\t'); cursor += 2; continue; }
                if (next == 'r') { out.push_back('\r'); cursor += 2; continue; }
                out.push_back(next);
                cursor += 2;
                continue;
            }
            if (c == '"')
                break;
            out.push_back(c);
            ++cursor;
        }
        return out;
    }

    // 数字
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

    const std::string raw = read_all("tests/fixtures/veil_vectors.json");
    test::expect(!raw.empty(), "loads the cross implementation vectors");
    if (raw.empty())
        return test::finish("veil_vectors");

    // 逐条比对：C++ 侧的派生结果必须与 Node 侧逐字节相同
    std::size_t cursor = 0;
    std::size_t cases = 0;

    while (true) {
        const std::size_t at = raw.find("\"name\"", cursor);
        if (at == std::string::npos)
            break;
        cursor = at + 6;
        ++cases;

        const std::string name = field(raw, "name", at);
        const std::string card = field(raw, "cardKey", at);
        const std::string hwid = field(raw, "hwid", at);
        const std::string nonce_hex = field(raw, "nonceHex", at);
        const std::string evidence_hex = field(raw, "evidenceHex", at);
        const std::string domain_text = field(raw, "domain", at);
        const std::string key_hex = field(raw, "keyHex", at);

        if (card.empty() || key_hex.empty()) {
            test::expect(false, name.c_str());
            continue;
        }

        std::uint8_t nonce[license::SignedEnvelope::NONCE_SIZE];
        std::uint8_t evidence[1024];
        std::uint8_t expected[32];

        const std::size_t nonce_len =
            hex_to_bytes(nonce_hex, nonce, sizeof(nonce));
        const std::size_t evidence_len =
            hex_to_bytes(evidence_hex, evidence, sizeof(evidence));
        const std::size_t expected_len =
            hex_to_bytes(key_hex, expected, sizeof(expected));

        if (nonce_len != sizeof(nonce) || expected_len != 32) {
            test::expect(false, name.c_str());
            continue;
        }

        const auto domain = static_cast<std::uint8_t>(
            std::strtoul(domain_text.c_str(), nullptr, 10));

        const license::SignedEnvelope::Inputs inputs{
            card.data(), card.size(),
            hwid.empty() ? nullptr : hwid.data(), hwid.size(),
            evidence_len == 0 ? nullptr : evidence, evidence_len,
            domain};

        std::uint8_t derived[32];
        const bool ok = license::SignedEnvelope::derive_session_key(
            nonce, inputs, derived);

        const bool same = ok &&
                          detail::constant_time_compare(derived, expected, 32) == 1;
        test::expect(same, name.c_str());
    }

    test::expect(cases == 4, "exercised every cross implementation case");

    // 长度前缀的必要性：证据末字节与 HWID 首字节相同的两组输入，
    // 必须派生出不同密钥
    {
        std::uint8_t nonce[license::SignedEnvelope::NONCE_SIZE]{};

        std::uint8_t evidence_a[2] = {0x11, 0x22};
        const char hwid_a[] = "ABC";

        std::uint8_t evidence_b[1] = {0x11};
        const char hwid_b[] = "\x22" "ABC";

        const license::SignedEnvelope::Inputs first{
            "CARD", 4, hwid_a, 3, evidence_a, 2, 0x01};
        const license::SignedEnvelope::Inputs second{
            "CARD", 4, hwid_b, 4, evidence_b, 1, 0x01};

        std::uint8_t key_a[32];
        std::uint8_t key_b[32];
        license::SignedEnvelope::derive_session_key(nonce, first, key_a);
        license::SignedEnvelope::derive_session_key(nonce, second, key_b);

        test::expect(detail::constant_time_compare(key_a, key_b, 32) == 0,
                     "length prefix separates evidence and hwid boundaries");
    }

    // HWID 长度上限
    {
        std::uint8_t nonce[license::SignedEnvelope::NONCE_SIZE]{};
        char too_long[license::MAX_MACHINE_ID + 1];
        std::memset(too_long, 'H', sizeof(too_long));

        const license::SignedEnvelope::Inputs inputs{
            "CARD", 4, too_long, sizeof(too_long), nullptr, 0, 0x01};

        std::uint8_t derived[32];
        test::expect(!license::SignedEnvelope::derive_session_key(
                         nonce, inputs, derived),
                     "hwid above the bound is rejected");
    }

    return test::finish("veil_vectors");
}
