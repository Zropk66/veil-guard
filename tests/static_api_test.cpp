#include <veil/detail/common.hpp>
#include <veil/static_api.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    const char card_key[] = "VEIL-STATIC-KEY-1";
    std::uint8_t nonce[16];
    for (std::size_t i = 0; i < sizeof(nonce); ++i)
        nonce[i] = static_cast<std::uint8_t>(i * 11 + 3);

    // 证据采集必须给出确定长度且可重复
    {
        std::uint8_t buffer[1024];
        std::size_t written = 0;
        test::expect(veil_capture_standard_evidence(buffer, sizeof(buffer),
                                                    &written),
                     "captures the standard evidence");
        test::expect(written == 16 + 20 + 32,
                     "evidence blob covers the three standard providers");

        std::uint8_t again[1024];
        std::size_t written_again = 0;
        veil_capture_standard_evidence(again, sizeof(again), &written_again);
        test::expect(written_again == written, "evidence size is stable");
        test::expect(detail::constant_time_compare(buffer, again, written) == 1,
                     "evidence bytes are stable across captures");
    }

    // 采集失败的条件
    {
        std::uint8_t buffer[1024];
        std::size_t written = 0;
        test::expect(!veil_capture_standard_evidence(nullptr, sizeof(buffer),
                                                     &written),
                     "null output is rejected");
        test::expect(!veil_capture_standard_evidence(buffer, sizeof(buffer),
                                                     nullptr),
                     "null size output is rejected");
        test::expect(!veil_capture_standard_evidence(buffer, 8, &written),
                     "insufficient capacity is rejected");
    }

    // 环境派生：同一环境重复派生必须一致
    {
        std::uint8_t key_a[32];
        std::uint8_t key_b[32];
        test::expect(veil_derive_from_environment(card_key, sizeof(card_key) - 1,
                                                  nonce, sizeof(nonce), 0x01,
                                                  key_a, sizeof(key_a)),
                     "derives a session key from the environment");
        test::expect(veil_derive_from_environment(card_key, sizeof(card_key) - 1,
                                                  nonce, sizeof(nonce), 0x01,
                                                  key_b, sizeof(key_b)),
                     "repeats the environment derivation");
        test::expect(detail::constant_time_compare(key_a, key_b, 32) == 1,
                     "environment derivation is reproducible");
    }

    // 环境派生必须与显式采集后派生一致
    {
        std::uint8_t evidence[1024];
        std::size_t written = 0;
        veil_capture_standard_evidence(evidence, sizeof(evidence), &written);

        std::uint8_t direct[32];
        test::expect(veil_derive_session_key(card_key, sizeof(card_key) - 1,
                                             nonce, sizeof(nonce), evidence,
                                             written, 0x01, direct,
                                             sizeof(direct)),
                     "derives from explicit evidence");

        std::uint8_t combined[32];
        veil_derive_from_environment(card_key, sizeof(card_key) - 1, nonce,
                                     sizeof(nonce), 0x01, combined,
                                     sizeof(combined));
        test::expect(detail::constant_time_compare(direct, combined, 32) == 1,
                     "both entry points derive the same key");
    }

    // 域字节隔离
    {
        std::uint8_t domain_a[32];
        std::uint8_t domain_b[32];
        veil_derive_from_environment(card_key, sizeof(card_key) - 1, nonce,
                                     sizeof(nonce), 0x01, domain_a,
                                     sizeof(domain_a));
        veil_derive_from_environment(card_key, sizeof(card_key) - 1, nonce,
                                     sizeof(nonce), 0x02, domain_b,
                                     sizeof(domain_b));
        test::expect(detail::constant_time_compare(domain_a, domain_b, 32) == 0,
                     "domain separates environment derivations");
    }

    // 输入校验
    {
        std::uint8_t key[32];
        test::expect(!veil_derive_from_environment(nullptr, 0, nonce,
                                                    sizeof(nonce), 0x01, key,
                                                    sizeof(key)),
                     "null key material is rejected");
        test::expect(!veil_derive_from_environment(card_key, sizeof(card_key) - 1,
                                                   nonce, sizeof(nonce), 0x01,
                                                   nullptr, 32),
                     "null output is rejected");
        test::expect(!veil_derive_from_environment(card_key, sizeof(card_key) - 1,
                                                   nonce, sizeof(nonce), 0x01,
                                                   key, 8),
                     "undersized output is rejected");
        test::expect(!veil_derive_session_key(card_key, sizeof(card_key) - 1,
                                              nonce, sizeof(nonce), nullptr, 0,
                                              0x01, key, sizeof(key)),
                     "null evidence is rejected");
    }

    return test::finish("static_api");
}
