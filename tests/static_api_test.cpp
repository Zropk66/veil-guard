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

    // 布局 2：含代码完整性观测
    {
        std::uint8_t buffer[1024];
        std::size_t written = 0;
        std::size_t failures = 0;

        test::expect(veil_capture_integrity_evidence(buffer, sizeof(buffer),
                                                      &written, &failures),
                     "captures the integrity evidence");
        test::expect(written == INTEGRITY_EVIDENCE_SIZE,
                     "integrity evidence covers the registered layout");
        test::expect(written == 328, "integrity evidence is 328 bytes");

        // 正常环境下磁盘与内存摘要一致，差值槽位全零。区域计数非零
        // 是布局描述，不是判定值。
        bool deltas_zero = true;
        for (std::size_t i = sizeof(std::uint32_t) + 68; i < written; ++i)
            if (buffer[i] != 0)
                deltas_zero = false;
        test::expect(deltas_zero,
                     "untampered code integrity deltas are zero");

        // 重复采集必须稳定
        std::uint8_t again[1024];
        std::size_t written_again = 0;
        veil_capture_integrity_evidence(again, sizeof(again), &written_again,
                                        nullptr);
        test::expect(written_again == written,
                     "integrity evidence size is stable");
        test::expect(detail::constant_time_compare(buffer, again, written) == 1,
                     "integrity evidence is stable across captures");
    }

    // 布局 2 的输入校验
    {
        std::uint8_t buffer[1024];
        std::size_t written = 0;
        test::expect(!veil_capture_integrity_evidence(nullptr, sizeof(buffer),
                                                       &written, nullptr),
                     "integrity capture rejects a null output");
        test::expect(!veil_capture_integrity_evidence(buffer, sizeof(buffer),
                                                       nullptr, nullptr),
                     "integrity capture rejects a null size output");
        test::expect(!veil_capture_integrity_evidence(buffer, 16, &written,
                                                       nullptr),
                     "integrity capture rejects insufficient capacity");
    }

    // 两套布局必须派生出不同密钥
    {
        std::uint8_t standard[1024];
        std::size_t standard_len = 0;
        std::uint8_t integrity[1024];
        std::size_t integrity_len = 0;

        veil_capture_standard_evidence(standard, sizeof(standard), &standard_len);
        veil_capture_integrity_evidence(integrity, sizeof(integrity),
                                        &integrity_len, nullptr);

        std::uint8_t key_standard[32];
        std::uint8_t key_integrity[32];
        veil_derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                sizeof(nonce), standard, standard_len, 0x01,
                                key_standard, sizeof(key_standard));
        veil_derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                sizeof(nonce), integrity, integrity_len, 0x01,
                                key_integrity, sizeof(key_integrity));

        test::expect(detail::constant_time_compare(key_standard, key_integrity,
                                                   32) == 0,
                     "the two layouts derive different keys");
    }

    // 布局 2 的直接派生入口
    {
        std::uint8_t key_a[32];
        std::uint8_t key_b[32];
        test::expect(veil_derive_with_integrity(card_key, sizeof(card_key) - 1,
                                                 nonce, sizeof(nonce), 0x01,
                                                 key_a, sizeof(key_a)),
                     "derives with integrity evidence");
        test::expect(veil_derive_with_integrity(card_key, sizeof(card_key) - 1,
                                                 nonce, sizeof(nonce), 0x01,
                                                 key_b, sizeof(key_b)),
                     "repeats the integrity derivation");
        test::expect(detail::constant_time_compare(key_a, key_b, 32) == 1,
                     "integrity derivation is reproducible");

        // 与标准布局的派生结果必须不同
        std::uint8_t standard_key[32];
        veil_derive_from_environment(card_key, sizeof(card_key) - 1, nonce,
                                     sizeof(nonce), 0x01, standard_key,
                                     sizeof(standard_key));
        test::expect(detail::constant_time_compare(key_a, standard_key, 32) == 0,
                     "integrity derivation differs from the standard one");

        test::expect(!veil_derive_with_integrity(nullptr, 0, nonce,
                                                  sizeof(nonce), 0x01, key_a,
                                                  sizeof(key_a)),
                     "integrity derivation rejects a null key");
        test::expect(!veil_derive_with_integrity(card_key, sizeof(card_key) - 1,
                                                  nonce, sizeof(nonce), 0x01,
                                                  nullptr, 32),
                     "integrity derivation rejects a null output");
        test::expect(!veil_derive_with_integrity(card_key, sizeof(card_key) - 1,
                                                  nonce, sizeof(nonce), 0x01,
                                                  key_a, 8),
                     "integrity derivation rejects an undersized output");
    }

    return test::finish("static_api");
}
