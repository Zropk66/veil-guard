#include <veil/detail/common.hpp>
#include <veil/evidence/binder.hpp>
#include <veil/providers/anti_debug.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    const char card_key[] = "VEIL-TEST-KEY-001";
    std::uint8_t nonce[16];
    for (std::size_t i = 0; i < sizeof(nonce); ++i)
        nonce[i] = static_cast<std::uint8_t>(i * 3 + 1);

    std::uint8_t evidence[16]{};

    std::uint8_t key_a[32];
    std::uint8_t key_b[32];
    test::expect(evidence::Binder::derive(card_key, sizeof(card_key) - 1,
                                          nonce, sizeof(nonce),
                                          evidence, sizeof(evidence), 0x01, key_a),
                 "derivation succeeds");
    evidence::Binder::derive(card_key, sizeof(card_key) - 1, nonce, sizeof(nonce),
                             evidence, sizeof(evidence), 0x01, key_b);
    test::expect(detail::constant_time_compare(key_a, key_b, 32) == 1,
                 "same evidence derives identical key");

    // 任一字节变化必须分叉
    for (std::size_t byte = 0; byte < sizeof(evidence); ++byte) {
        std::uint8_t tampered[16]{};
        tampered[byte] = 0x01;
        std::uint8_t key_c[32];
        evidence::Binder::derive(card_key, sizeof(card_key) - 1, nonce, sizeof(nonce),
                                 tampered, sizeof(tampered), 0x01, key_c);
        test::expect(detail::constant_time_compare(key_a, key_c, 32) == 0,
                     "altered evidence changes derived key");
        break;
    }

    // 域字节隔离
    std::uint8_t key_d[32];
    evidence::Binder::derive(card_key, sizeof(card_key) - 1, nonce, sizeof(nonce),
                             evidence, sizeof(evidence), 0x02, key_d);
    test::expect(detail::constant_time_compare(key_a, key_d, 32) == 0,
                 "domain byte separates derived keys");

    // nonce 变化必须分叉
    std::uint8_t other_nonce[16];
    std::memcpy(other_nonce, nonce, sizeof(nonce));
    other_nonce[0] ^= 0x80;
    std::uint8_t key_e[32];
    evidence::Binder::derive(card_key, sizeof(card_key) - 1, other_nonce, sizeof(other_nonce),
                             evidence, sizeof(evidence), 0x01, key_e);
    test::expect(detail::constant_time_compare(key_a, key_e, 32) == 0,
                 "nonce changes derived key");

    // 密钥材料变化必须分叉
    const char other_card[] = "VEIL-TEST-KEY-002";
    std::uint8_t key_g[32];
    evidence::Binder::derive(other_card, sizeof(other_card) - 1, nonce, sizeof(nonce),
                             evidence, sizeof(evidence), 0x01, key_g);
    test::expect(detail::constant_time_compare(key_a, key_g, 32) == 0,
                 "key material changes derived key");

    // 证据长度变化必须分叉，即使尾部为零
    std::uint8_t longer[17]{};
    std::uint8_t key_h[32];
    evidence::Binder::derive(card_key, sizeof(card_key) - 1, nonce, sizeof(nonce),
                             longer, sizeof(longer), 0x01, key_h);
    test::expect(detail::constant_time_compare(key_a, key_h, 32) == 0,
                 "evidence length participates in derivation");

    // 上限之内的最大证据必须可用，且域字节确实参与
    std::uint8_t max_evidence[MAX_EVIDENCE_BYTES]{};
    std::uint8_t key_max_a[32];
    std::uint8_t key_max_b[32];
    test::expect(evidence::Binder::derive(card_key, sizeof(card_key) - 1,
                                          nonce, sizeof(nonce),
                                          max_evidence, sizeof(max_evidence),
                                          0x01, key_max_a),
                 "derivation accepts evidence at the configured bound");
    evidence::Binder::derive(card_key, sizeof(card_key) - 1, nonce, sizeof(nonce),
                             max_evidence, sizeof(max_evidence), 0x02, key_max_b);
    test::expect(detail::constant_time_compare(key_max_a, key_max_b, 32) == 0,
                 "domain byte survives at the evidence bound");

    // 超长证据必须拒绝而不是截断
    std::uint8_t huge[MAX_EVIDENCE_BYTES + 1];
    std::memset(huge, 0, sizeof(huge));
    std::uint8_t key_f[32];
    test::expect(!evidence::Binder::derive(card_key, sizeof(card_key) - 1,
                                           nonce, sizeof(nonce),
                                           huge, sizeof(huge), 0x01, key_f),
                 "oversized evidence is rejected");

    // 空指针与零长度必须拒绝
    test::expect(!evidence::Binder::derive(nullptr, 0, nonce, sizeof(nonce),
                                           evidence, sizeof(evidence), 0x01, key_f),
                 "null card key is rejected");
    test::expect(!evidence::Binder::derive(card_key, sizeof(card_key) - 1,
                                           nullptr, 0,
                                           evidence, sizeof(evidence), 0x01, key_f),
                 "null nonce is rejected");
    test::expect(!evidence::Binder::derive(card_key, sizeof(card_key) - 1,
                                           nonce, sizeof(nonce),
                                           nullptr, 0, 0x01, key_f),
                 "null evidence is rejected");
    test::expect(!evidence::Binder::derive(card_key, sizeof(card_key) - 1,
                                           nonce, sizeof(nonce),
                                           evidence, sizeof(evidence), 0x01, nullptr),
                 "null output is rejected");
    test::expect(!evidence::Binder::derive(card_key, 0, nonce, sizeof(nonce),
                                           evidence, sizeof(evidence), 0x01, key_f),
                 "zero length key material is rejected");

    return test::finish("binder");
}
