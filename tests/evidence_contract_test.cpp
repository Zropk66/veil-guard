#include <veil/config.hpp>
#include <veil/detail/common.hpp>
#include <veil/evidence/binder.hpp>
#include <veil/evidence/layout.hpp>
#include <veil/providers/anti_debug.hpp>
#include <veil/providers/cert_pin.hpp>
#include <veil/providers/code_integrity.hpp>
#include <veil/providers/module_topo.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    // 标准布局的长度是对外契约。服务端用零基线按同一长度构造 info，
    // 这里的断言把它钉住，改动 provider 组合会立刻失败而不是静默
    // 让全部客户端派生分叉。
    using Standard = evidence::Layout<providers::AntiDebugSnapshot,
                                      providers::ModuleTopology,
                                      providers::CertificatePin>;

    test::expect(Standard::SIZE == STANDARD_EVIDENCE_SIZE,
                 "standard layout matches the published contract");
    test::expect(STANDARD_EVIDENCE_SIZE == 68,
                 "the contract value is 68 bytes");
    test::expect(Standard::SIZE ==
                     providers::AntiDebugSnapshot::OBSERVATION_SIZE +
                         providers::ModuleTopology::OBSERVATION_SIZE +
                         providers::CertificatePin::OBSERVATION_SIZE,
                 "layout length is the sum of its providers");

    // 各 provider 的单独长度
    test::expect(providers::AntiDebugSnapshot::OBSERVATION_SIZE == 16,
                 "anti-debug observation is 16 bytes");
    test::expect(providers::ModuleTopology::OBSERVATION_SIZE == 20,
                 "module topology observation is 20 bytes");
    test::expect(providers::CertificatePin::OBSERVATION_SIZE == 32,
                 "certificate pin observation is 32 bytes");

    // 正常环境下标准布局必须逐字节为零。服务端的期望值就是这个，
    // 客户端测到任何非零都会导致派生分叉。
    {
        const providers::AntiDebugSnapshot debug_probe;
        const providers::ModuleTopology topo_probe;
        const providers::CertificatePin pin_probe;

        std::uint8_t buffer[Standard::SIZE];
        std::memset(buffer, 0xCC, sizeof(buffer));
        test::expect(Standard::serialize(buffer, sizeof(buffer), debug_probe,
                                          topo_probe, pin_probe),
                     "standard layout serializes");

        // 反调试与证书指纹必须全零。模块拓扑在测试进程里可能非零，
        // 因为它从构建目录加载，不属于任何可信前缀。
        bool debug_zero = true;
        const std::uint8_t* bytes = buffer;
        for (std::size_t i = 0; i < 16; ++i)
            if (bytes[i] != 0)
                debug_zero = false;
        test::expect(debug_zero, "anti-debug portion is zero when undebugged");

        bool pin_zero = true;
        for (std::size_t i = 36; i < 68; ++i)
            if (bytes[i] != 0)
                pin_zero = false;
        test::expect(pin_zero, "certificate pin portion is zero without tls");
    }

    // 布局标识与服务端登记表的键必须一一对应。客户端在请求中声明该
    // 标识，服务端据此选择零基线长度。标识与长度任一处改动都必须
    // 两侧同步，否则派生分叉。
    {
        test::expect(std::strcmp(EVIDENCE_LAYOUT_STANDARD, "1") == 0,
                     "the standard layout id is 1");
        test::expect(std::strcmp(EVIDENCE_LAYOUT_INTEGRITY, "2") == 0,
                     "the integrity layout id is 2");
    }

    // 含代码完整性 provider 的布局
    {
        using Integrity = evidence::Layout<providers::AntiDebugSnapshot,
                                           providers::ModuleTopology,
                                           providers::CertificatePin,
                                           providers::CodeIntegrity>;

        test::expect(Integrity::SIZE == INTEGRITY_EVIDENCE_SIZE,
                     "integrity layout matches the published contract");
        test::expect(INTEGRITY_EVIDENCE_SIZE == 328,
                     "the integrity contract value is 328 bytes");
        test::expect(providers::CodeIntegrity::OBSERVATION_SIZE == 260,
                     "code integrity observation is 260 bytes");
        test::expect(Integrity::SIZE == STANDARD_EVIDENCE_SIZE +
                                            providers::CodeIntegrity::OBSERVATION_SIZE,
                     "integrity layout extends the standard layout");
        test::expect(INTEGRITY_EVIDENCE_SIZE > STANDARD_EVIDENCE_SIZE,
                     "the two layouts are distinguishable by length");
    }

    // 两套布局必须派生出不同密钥，否则布局标识形同虚设
    {
        std::uint8_t key_standard[32];
        std::uint8_t key_integrity[32];
        std::uint8_t nonce[16]{};
        const char card[] = "VEIL-LAYOUT-KEY";

        std::uint8_t standard[STANDARD_EVIDENCE_SIZE]{};
        std::uint8_t integrity[INTEGRITY_EVIDENCE_SIZE]{};

        evidence::Binder::derive(card, sizeof(card) - 1, nonce, sizeof(nonce),
                                 standard, sizeof(standard), 0x01, key_standard);
        evidence::Binder::derive(card, sizeof(card) - 1, nonce, sizeof(nonce),
                                 integrity, sizeof(integrity), 0x01, key_integrity);

        test::expect(detail::constant_time_compare(key_standard, key_integrity,
                                                   32) == 0,
                     "the two layouts derive different keys");
    }

    // 长度不符的证据必须被 Binder 以不同密钥回应，而不是被静默接受
    {
        std::uint8_t key_a[32];
        std::uint8_t key_b[32];
        std::uint8_t nonce[16]{};
        const char card[] = "VEIL-CONTRACT-KEY";

        std::uint8_t standard[STANDARD_EVIDENCE_SIZE]{};
        std::uint8_t other[STANDARD_EVIDENCE_SIZE - 1]{};

        evidence::Binder::derive(card, sizeof(card) - 1, nonce, sizeof(nonce),
                                 standard, sizeof(standard), 0x01, key_a);
        evidence::Binder::derive(card, sizeof(card) - 1, nonce, sizeof(nonce),
                                 other, sizeof(other), 0x01, key_b);

        test::expect(detail::constant_time_compare(key_a, key_b, 32) == 0,
                     "a different evidence length derives a different key");
    }

    return test::finish("evidence_contract");
}
