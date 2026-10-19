#include <veil/config.hpp>
#include <veil/detail/common.hpp>
#include <veil/evidence/binder.hpp>
#include <veil/evidence/layout.hpp>
#include <veil/providers/anti_debug.hpp>
#include <veil/providers/cert_pin.hpp>
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
