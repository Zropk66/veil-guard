#include <veil/detail/common.hpp>
#include <veil/license/envelope.hpp>
#include <veil/license/payload.hpp>
#include "support/test_main.hpp"

#include <cstring>

namespace {

struct DemoPayload {
    std::uint64_t issued_at;
    std::uint64_t expires_at;
    std::uint32_t feature_mask;
    std::uint32_t reserved;
};

}  // namespace

static_assert(veil::license::PayloadLike<DemoPayload>);

int main() {
    using namespace veil;

    test::expect(sizeof(DemoPayload) == 24, "demo payload is 24 bytes");

    // 时效折算：过期返回 0，永久返回全掩码
    {
        DemoPayload payload{};
        payload.issued_at = 1000;
        payload.expires_at = 2000;
        payload.feature_mask = 0x0F;

        test::expect(license::effective_mask(payload, 1500) == 0x0F,
                     "unexpired payload yields full mask");
        test::expect(license::effective_mask(payload, 2000) == 0,
                     "payload expiring exactly now yields zero mask");
        test::expect(license::effective_mask(payload, 2500) == 0,
                     "expired payload yields zero mask");

        payload.expires_at = 0;
        test::expect(license::effective_mask(payload, 999999999) == 0x0F,
                     "perpetual payload never expires");

        // 签发时间超前本地时钟超过一小时视为时钟回拨。
        // 一小时容差边界两侧各取一个样本。
        payload.issued_at = 1000 + 3600 * 1000;
        payload.expires_at = 0;
        test::expect(license::effective_mask(payload, 1000) == 0x0F,
                     "issued_at at the clock skew bound is accepted");
        payload.issued_at = 1000 + 3600 * 1000 + 1;
        test::expect(license::effective_mask(payload, 1000) == 0,
                     "future issued_at beyond the skew bound is rejected");
    }

    // 信封往返：用固定密钥与 nonce 验证 seal 与 open 对称
    {
        const char card_key[] = "VEIL-CARD-0001";
        const char machine_id[] = "MACHINE-ABC-123";

        std::uint8_t nonce[license::NONCE_SIZE];
        for (std::size_t i = 0; i < sizeof(nonce); ++i)
            nonce[i] = static_cast<std::uint8_t>(i + 1);

        DemoPayload payload{};
        payload.issued_at = 1000;
        payload.expires_at = 0;
        payload.feature_mask = 0x03;

        DemoPayload sealed = payload;
        std::uint8_t binding[license::BINDING_SIZE];
        test::expect(license::compute_binding(
                         card_key, sizeof(card_key) - 1, nonce,
                         machine_id, sizeof(machine_id) - 1,
                         &sealed, sizeof(sealed), binding),
                     "computes binding over payload");
        test::expect(license::xor_stream(
                         card_key, sizeof(card_key) - 1, nonce,
                         machine_id, sizeof(machine_id) - 1,
                         &sealed, sizeof(sealed)),
                     "applies key stream");
        test::expect(std::memcmp(&sealed, &payload, sizeof(payload)) != 0,
                     "sealed payload differs from plaintext");

        // 同参数重算密钥流必须还原明文
        DemoPayload recovered = sealed;
        test::expect(license::xor_stream(
                         card_key, sizeof(card_key) - 1, nonce,
                         machine_id, sizeof(machine_id) - 1,
                         &recovered, sizeof(recovered)),
                     "reapplies key stream");
        test::expect(std::memcmp(&recovered, &payload, sizeof(payload)) == 0,
                     "key stream round trip restores payload");

        // 换机器必须解不出正确明文
        const char other_machine[] = "MACHINE-XYZ-999";
        DemoPayload wrong = sealed;
        license::xor_stream(card_key, sizeof(card_key) - 1, nonce,
                            other_machine, sizeof(other_machine) - 1,
                            &wrong, sizeof(wrong));
        test::expect(std::memcmp(&wrong, &payload, sizeof(payload)) != 0,
                     "wrong machine id produces garbage plaintext");

        // 换卡密必须解不出正确明文
        const char other_card[] = "VEIL-CARD-0002";
        DemoPayload wrong_card = sealed;
        license::xor_stream(other_card, sizeof(other_card) - 1, nonce,
                            machine_id, sizeof(machine_id) - 1,
                            &wrong_card, sizeof(wrong_card));
        test::expect(std::memcmp(&wrong_card, &payload, sizeof(payload)) != 0,
                     "wrong card key produces garbage plaintext");

        // 绑定校验必须对机器标识敏感，且自身确定
        std::uint8_t other_binding[license::BINDING_SIZE];
        license::compute_binding(card_key, sizeof(card_key) - 1, nonce,
                                 other_machine, sizeof(other_machine) - 1,
                                 &sealed, sizeof(sealed), other_binding);
        test::expect(detail::constant_time_compare(binding, other_binding,
                                                   license::BINDING_SIZE) == 0,
                     "binding diverges on a different machine id");

        std::uint8_t repeat[license::BINDING_SIZE];
        DemoPayload pristine = payload;
        license::compute_binding(card_key, sizeof(card_key) - 1, nonce,
                                 machine_id, sizeof(machine_id) - 1,
                                 &pristine, sizeof(pristine), repeat);
        test::expect(detail::constant_time_compare(binding, repeat,
                                                   license::BINDING_SIZE) == 1,
                     "binding is deterministic");

        // 超长机器标识必须显式失败，不截断
        char long_machine[license::MAX_MACHINE_ID + 2];
        std::memset(long_machine, 'A', sizeof(long_machine));
        std::uint8_t long_binding[license::BINDING_SIZE];
        test::expect(!license::compute_binding(
                         card_key, sizeof(card_key) - 1, nonce,
                         long_machine, sizeof(long_machine),
                         &sealed, sizeof(sealed), long_binding),
                     "oversized machine id is rejected");

        // 上限之内的最长标识必须可用
        char max_machine[license::MAX_MACHINE_ID];
        std::memset(max_machine, 'A', sizeof(max_machine));
        test::expect(license::compute_binding(
                         card_key, sizeof(card_key) - 1, nonce,
                         max_machine, sizeof(max_machine),
                         &sealed, sizeof(sealed), long_binding),
                     "machine id at the bound is accepted");

        // 空机器标识必须可用，未启用绑定的授权依赖此路径
        std::uint8_t empty_binding[license::BINDING_SIZE];
        test::expect(license::compute_binding(card_key, sizeof(card_key) - 1, nonce,
                                              nullptr, 0, &sealed, sizeof(sealed),
                                              empty_binding),
                     "empty machine id is accepted");
        test::expect(detail::constant_time_compare(binding, empty_binding,
                                                   license::BINDING_SIZE) == 0,
                     "unbound binding differs from a bound one");
    }

    // 密钥流上限
    {
        const char card_key[] = "VEIL-CARD-0001";
        std::uint8_t nonce[license::NONCE_SIZE]{};
        std::uint8_t oversized[513]{};
        test::expect(!license::xor_stream(card_key, sizeof(card_key) - 1, nonce,
                                          nullptr, 0, oversized, sizeof(oversized)),
                     "oversized payload is rejected");
        test::expect(!license::xor_stream(card_key, sizeof(card_key) - 1, nonce,
                                          nullptr, 0, oversized, 0),
                     "zero length payload is rejected");
        test::expect(!license::xor_stream(card_key, sizeof(card_key) - 1, nonce,
                                          nullptr, 0, nullptr, 16),
                     "null payload is rejected");
    }

    return test::finish("envelope");
}
