#include <veil/veil.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    // 总入口必须自足：单文件引用即可用，且各层符号可见
    test::expect(BUILD_SEED != 0, "build seed is injected");

    std::uint8_t digest[32];
    Sha256::hash("veil", 4, digest);
    bool digest_nonzero = false;
    for (std::size_t i = 0; i < sizeof(digest); ++i)
        if (digest[i] != 0)
            digest_nonzero = true;
    test::expect(digest_nonzero, "crypto layer is reachable through the umbrella header");

    const providers::AntiDebugSnapshot debug_probe;
    const providers::CertificatePin pin_probe;
    const providers::ModuleTopology topo_probe;

    using Layout = evidence::Layout<providers::AntiDebugSnapshot,
                                    providers::CertificatePin,
                                    providers::ModuleTopology>;
    std::uint8_t blob[Layout::SIZE];
    test::expect(Layout::serialize(blob, sizeof(blob), debug_probe, pin_probe,
                                   topo_probe),
                 "evidence layer is reachable through the umbrella header");

    std::uint8_t key[32];
    const char card[] = "VEIL-UMBRELLA-KEY";
    std::uint8_t nonce[16]{};
    test::expect(evidence::Binder::derive(card, sizeof(card) - 1, nonce,
                                          sizeof(nonce), blob, sizeof(blob),
                                          0x01, key),
                 "derivation is reachable through the umbrella header");

    // 平台层同样可用
    test::expect(platform::module_count() > 0, "platform layer enumerates modules");
    test::expect(platform::syscall_number("NtClose") != 0,
                 "platform layer resolves syscall numbers");

    // 授权层
    struct Demo {
        std::uint64_t issued_at;
        std::uint64_t expires_at;
        std::uint32_t feature_mask;
        std::uint32_t reserved;
    };
    Demo payload{};
    payload.issued_at = 1000;
    payload.expires_at = 2000;
    payload.feature_mask = 0x0F;
    test::expect(license::effective_mask(payload, 1500) == 0x0F,
                 "license layer is reachable through the umbrella header");

    // Guard 装配入口
    Guard guard;
    std::uint8_t session[32];
    test::expect(guard.derive_session_key(card, sizeof(card) - 1, nonce,
                                          sizeof(nonce), 0x01, session,
                                          debug_probe, pin_probe, topo_probe),
                 "guard assembly works through the umbrella header");

    return test::finish("umbrella");
}
