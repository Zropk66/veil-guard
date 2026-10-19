#include <veil/detail/common.hpp>
#include <veil/evidence/binder.hpp>
#include <veil/license/envelope.hpp>
#include "support/test_main.hpp"

#include <cstdio>
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

bool parse_hex(const std::string& json, const char* key,
               std::uint8_t* out, std::size_t size) {
    const std::string needle = std::string("\"") + key + "\"";
    const std::size_t at = json.find(needle);
    if (at == std::string::npos)
        return false;

    std::size_t cursor = json.find('"', json.find(':', at));
    if (cursor == std::string::npos)
        return false;
    ++cursor;

    for (std::size_t i = 0; i < size; ++i) {
        const int high = hex_nibble(json[cursor + i * 2]);
        const int low = hex_nibble(json[cursor + i * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

}  // namespace

int main() {
    using namespace veil;

    const std::string json = read_all("tests/vectors.json");
    test::expect(!json.empty(), "cross implementation vectors were generated");
    if (json.empty())
        return test::finish("vectors");

    const char card_key[] = "VEIL-CARD-0001";
    std::uint8_t nonce[16];
    std::uint8_t zero_evidence[64];
    std::uint8_t bound_evidence[64];
    std::uint8_t node_zero_key[32];
    std::uint8_t node_bound_key[32];
    std::uint8_t node_machine_id[15];
    std::uint8_t node_keystream_key[32];
    std::uint8_t node_binding_key[32];

    test::expect(parse_hex(json, "nonceHex", nonce, sizeof(nonce)),
                 "parses nonce from the fixture");
    test::expect(parse_hex(json, "zeroEvidenceHex", zero_evidence,
                           sizeof(zero_evidence)),
                 "parses zero baseline evidence");
    test::expect(parse_hex(json, "boundEvidenceHex", bound_evidence,
                           sizeof(bound_evidence)),
                 "parses deviating evidence");
    test::expect(parse_hex(json, "zeroEvidenceKeyHex", node_zero_key,
                           sizeof(node_zero_key)),
                 "parses the node derived key for the zero baseline");
    test::expect(parse_hex(json, "boundEvidenceKeyHex", node_bound_key,
                           sizeof(node_bound_key)),
                 "parses the node derived key for the deviating evidence");
    test::expect(parse_hex(json, "machineIdHex", node_machine_id,
                           sizeof(node_machine_id)),
                 "parses the machine id");
    test::expect(parse_hex(json, "keystreamKeyHex", node_keystream_key,
                           sizeof(node_keystream_key)),
                 "parses the node keystream key");
    test::expect(parse_hex(json, "bindingKeyHex", node_binding_key,
                           sizeof(node_binding_key)),
                 "parses the node binding key");

    // 证据派生必须与 Node 逐字节一致
    std::uint8_t local_zero_key[32];
    std::uint8_t local_bound_key[32];
    evidence::Binder::derive(card_key, sizeof(card_key) - 1, nonce, sizeof(nonce),
                             zero_evidence, sizeof(zero_evidence), 0x01,
                             local_zero_key);
    evidence::Binder::derive(card_key, sizeof(card_key) - 1, nonce, sizeof(nonce),
                             bound_evidence, sizeof(bound_evidence), 0x01,
                             local_bound_key);
    test::expect(detail::constant_time_compare(local_zero_key, node_zero_key, 32) == 1,
                 "zero baseline derivation matches node");
    test::expect(detail::constant_time_compare(local_bound_key, node_bound_key, 32) == 1,
                 "deviating evidence derivation matches node");
    test::expect(detail::constant_time_compare(local_zero_key, local_bound_key, 32) == 0,
                 "the two fixtures derive different keys");

    // 机器绑定派生必须与 Node 逐字节一致
    std::uint8_t local_keystream_key[32];
    std::uint8_t local_binding_key[32];
    license::derive_machine_key(card_key, sizeof(card_key) - 1, nonce,
                                sizeof(nonce),
                                node_machine_id, sizeof(node_machine_id),
                                license::DOMAIN_KEYSTREAM,
                                local_keystream_key, sizeof(local_keystream_key));
    license::derive_machine_key(card_key, sizeof(card_key) - 1, nonce,
                                sizeof(nonce),
                                node_machine_id, sizeof(node_machine_id),
                                license::DOMAIN_BINDING,
                                local_binding_key, sizeof(local_binding_key));
    test::expect(detail::constant_time_compare(local_keystream_key,
                                               node_keystream_key, 32) == 1,
                 "keystream key derivation matches node");
    test::expect(detail::constant_time_compare(local_binding_key,
                                               node_binding_key, 32) == 1,
                 "binding key derivation matches node");
    test::expect(detail::constant_time_compare(local_keystream_key,
                                               local_binding_key, 32) == 0,
                 "domain separation holds across implementations");

    return test::finish("vectors");
}
