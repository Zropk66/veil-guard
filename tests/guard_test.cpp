#include <veil/detail/common.hpp>
#include <veil/guard.hpp>
#include <veil/providers/anti_debug.hpp>
#include <veil/providers/cert_pin.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    const char card_key[] = "VEIL-GUARD-KEY-01";
    std::uint8_t nonce[16];
    for (std::size_t i = 0; i < sizeof(nonce); ++i)
        nonce[i] = static_cast<std::uint8_t>(i * 7 + 2);

    const providers::AntiDebugSnapshot debug_probe;
    const providers::CertificatePin pin_probe;

    // 同一组 provider 重复派生必须得到同一密钥
    {
        Guard guard;
        std::uint8_t key_a[evidence::Binder::KEY_SIZE];
        std::uint8_t key_b[evidence::Binder::KEY_SIZE];

        test::expect(guard.derive_session_key(card_key, sizeof(card_key) - 1,
                                              nonce, sizeof(nonce), 0x01,
                                              key_a, debug_probe, pin_probe),
                     "guard derives a session key");
        test::expect(guard.derive_session_key(card_key, sizeof(card_key) - 1,
                                              nonce, sizeof(nonce), 0x01,
                                              key_b, debug_probe, pin_probe),
                     "guard derivation is repeatable");
        test::expect(detail::constant_time_compare(key_a, key_b, 32) == 1,
                     "guard derivation is deterministic");
    }

    // 布局由实参推导：增删 provider 必然改变派生结果
    {
        Guard guard;
        std::uint8_t with_pin[32];
        std::uint8_t without_pin[32];

        guard.derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                 sizeof(nonce), 0x01, with_pin,
                                 debug_probe, pin_probe);
        guard.derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                 sizeof(nonce), 0x01, without_pin,
                                 debug_probe);
        test::expect(detail::constant_time_compare(with_pin, without_pin, 32) == 0,
                     "layout composition changes the derived key");
    }

    // 域字节隔离
    {
        Guard guard;
        std::uint8_t domain_a[32];
        std::uint8_t domain_b[32];
        guard.derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                 sizeof(nonce), 0x01, domain_a,
                                 debug_probe, pin_probe);
        guard.derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                 sizeof(nonce), 0x02, domain_b,
                                 debug_probe, pin_probe);
        test::expect(detail::constant_time_compare(domain_a, domain_b, 32) == 0,
                     "domain separates guard derivations");
    }

    // 非零指纹必须改变派生结果：证书被替换即分叉
    {
        Guard guard;
        std::uint8_t empty_pin_key[32];
        std::uint8_t set_pin_key[32];

        std::uint8_t digest[32];
        for (std::size_t i = 0; i < sizeof(digest); ++i)
            digest[i] = static_cast<std::uint8_t>(i * 3 + 1);
        const providers::CertificatePin pinned(digest);

        guard.derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                 sizeof(nonce), 0x01, empty_pin_key,
                                 debug_probe, pin_probe);
        guard.derive_session_key(card_key, sizeof(card_key) - 1, nonce,
                                 sizeof(nonce), 0x01, set_pin_key,
                                 debug_probe, pinned);
        test::expect(detail::constant_time_compare(empty_pin_key, set_pin_key, 32) == 0,
                     "certificate pin participates in derivation");
    }

    // capture 必须与 Layout::serialize 一致
    {
        Guard guard;
        using Layout = evidence::Layout<providers::AntiDebugSnapshot,
                                        providers::CertificatePin>;
        std::uint8_t via_guard[Layout::SIZE];
        std::uint8_t via_layout[Layout::SIZE];

        test::expect(guard.capture(via_guard, sizeof(via_guard),
                                   debug_probe, pin_probe),
                     "guard captures the observation blob");
        test::expect(Layout::serialize(via_layout, sizeof(via_layout),
                                       debug_probe, pin_probe),
                     "layout serializes the same blob");
        test::expect(detail::constant_time_compare(via_guard, via_layout,
                                                   sizeof(via_guard)) == 1,
                     "guard capture matches direct layout serialization");
    }

    // 容量不足必须失败而不是部分写入
    {
        Guard guard;
        std::uint8_t tiny[8];
        test::expect(!guard.capture(tiny, sizeof(tiny), debug_probe, pin_probe),
                     "capture rejects insufficient capacity");
    }

    // 非法输入必须拒绝
    {
        Guard guard;
        std::uint8_t key[32];
        test::expect(!guard.derive_session_key(nullptr, 0, nonce, sizeof(nonce),
                                              0x01, key, debug_probe, pin_probe),
                     "guard rejects null key material");
        test::expect(!guard.derive_session_key(card_key, sizeof(card_key) - 1,
                                              nullptr, 0, 0x01, key,
                                              debug_probe, pin_probe),
                     "guard rejects null nonce");
    }

    return test::finish("guard");
}
