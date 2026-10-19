#include <veil/detail/common.hpp>
#include <veil/evidence/binder.hpp>
#include <veil/evidence/layout.hpp>
#include <veil/providers/anti_debug.hpp>
#include <veil/providers/cert_pin.hpp>
#include <veil/providers/code_integrity.hpp>
#include <veil/providers/module_topo.hpp>
#include "support/test_main.hpp"

#include <cstring>

namespace {

// 校验单个 provider 的观测是否满足零值基线。
template <typename Provider>
void expect_zero(const char* label) {
    const Provider probe;
    const veil::Observation observation = probe.observe();
    const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
    bool all_zero = true;
    for (std::size_t i = 0; i < observation.size; ++i)
        if (bytes[i] != 0)
            all_zero = false;
    veil::test::expect(all_zero, label);
}

}  // namespace

int main() {
    using namespace veil;

    expect_zero<providers::AntiDebugSnapshot>(
        "anti-debug observation is zero when undebugged");
    expect_zero<providers::CertificatePin>(
        "certificate pin observation is zero without tls");

    {
        providers::CodeIntegrity probe;
        test::expect(probe.register_module_sections(),
                     "registers executable sections for the baseline check");
        const Observation observation = probe.observe();
        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);

        // region_count 非零是布局描述，差值槽位必须全零
        bool deltas_zero = true;
        for (std::size_t i = sizeof(std::uint32_t); i < observation.size; ++i)
            if (bytes[i] != 0)
                deltas_zero = false;
        test::expect(deltas_zero,
                     "code integrity deltas are zero for untampered sections");
    }

    // 模块拓扑：测试进程从构建目录加载，必然被判定为外源。
    // 验证的是「计数与哈希同时非零」，而不是零值。
    {
        const providers::ModuleTopology probe;
        const Observation observation = probe.observe();
        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
        std::uint32_t foreign = 0;
        std::memcpy(&foreign, bytes, sizeof(foreign));

        bool hash_nonzero = false;
        for (std::size_t i = sizeof(foreign); i < observation.size; ++i)
            if (bytes[i] != 0)
                hash_nonzero = true;

        test::expect(foreign > 0,
                     "test binary is correctly classified as foreign");
        test::expect(hash_nonzero,
                     "foreign modules contribute to the path hash");
    }

    // 组合布局：序列化后必须与逐 provider 拼接逐字节一致
    {
        using Combined = evidence::Layout<providers::AntiDebugSnapshot,
                                          providers::CertificatePin>;
        std::uint8_t buffer[Combined::SIZE];
        const providers::AntiDebugSnapshot debug_probe;
        const providers::CertificatePin pin_probe;
        test::expect(Combined::serialize(buffer, sizeof(buffer),
                                         debug_probe, pin_probe),
                     "combined layout serializes");
        bool all_zero = true;
        for (std::size_t i = 0; i < sizeof(buffer); ++i)
            if (buffer[i] != 0)
                all_zero = false;
        test::expect(all_zero,
                     "combined undebugged untampered layout is all zero");
    }

    // 零证据必须能派生出确定的密钥，且与全零证据之外的内容分叉
    {
        std::uint8_t zero_evidence[64]{};
        std::uint8_t key_a[32];
        std::uint8_t key_b[32];
        const char card[] = "ZERO-BASELINE-KEY";
        std::uint8_t nonce[16]{};

        test::expect(evidence::Binder::derive(card, sizeof(card) - 1,
                                              nonce, sizeof(nonce),
                                              zero_evidence, sizeof(zero_evidence),
                                              0x01, key_a),
                     "zero baseline evidence derives a key");
        evidence::Binder::derive(card, sizeof(card) - 1, nonce, sizeof(nonce),
                                 zero_evidence, sizeof(zero_evidence), 0x01, key_b);
        test::expect(detail::constant_time_compare(key_a, key_b, 32) == 1,
                     "zero baseline derivation is reproducible");

        zero_evidence[0] = 0x01;
        std::uint8_t key_c[32];
        evidence::Binder::derive(card, sizeof(card) - 1, nonce, sizeof(nonce),
                                 zero_evidence, sizeof(zero_evidence), 0x01, key_c);
        test::expect(detail::constant_time_compare(key_a, key_c, 32) == 0,
                     "single bit deviation from the baseline forks the key");
    }

    return test::finish("zero_baseline");
}
