#pragma once

#include "../config.hpp"
#include "../crypto/aes_gcm.hpp"
#include "../crypto/ed25519.hpp"
#include "../detail/common.hpp"
#include "../evidence/binder.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::license {

// 签名信封。
//
// 解决的是「服务端下发授权，客户端如何确认这份授权确实来自服务端，
// 且未在传输中被改动」。
//
// 与 SecCore 的 ProtocolV2 的区别在于不协商会话密钥。veil 的两侧各自
// 用 HKDF 从卡密、nonce 与证据派生同一把密钥，服务端不需要客户端把
// 密钥发给它，因此不需要 RSA 包裹。省掉的是一条与核心模型并行的密钥
// 协商路径，那正是「多条派生路径可被误用」的成因。
//
// 防护顺序经过刻意安排：
//
//   验签 → 时间窗 → 派生 → 解密
//
// 验签只需公钥，是纯公开计算，放在最前。攻击者用垃圾密文冲击客户端
// 时会在验签阶段被挡住，既不消耗 HKDF 与 AES 的计算，也不让解密器
// 接触未认证的数据。若把解密放在验签之前，就等于给出一个解密 oracle。
//
// 签名覆盖 stamp ‖ nonce ‖ cipher ‖ tag，即信封的全部字节。改动其中
// 任何一字节，验签即失败。
//
// 密钥派生额外引入证据，与签名构成两条独立防线：签名防伪造，证据防
// 环境篡改。攻击者持有一份合法信封但改动了本机环境时，签名依然有效，
// 而派生出的是另一把密钥，GCM 标签校验失败。
//
// nonce 与 issued_at 同时作为 GCM 的附加认证数据。即便攻击者以某种
// 方式绕过验签，这两个字段也无法被替换。
//
// 服务端责任：同一密钥下 nonce 必须唯一。重复的 nonce 会让 GCM 的
// 密钥流重用，这是该模式的固有要求，库无法代为实现。
class SignedEnvelope {
public:
    static constexpr std::size_t NONCE_SIZE = Aes256Gcm::NONCE_SIZE;
    static constexpr std::size_t TAG_SIZE = Aes256Gcm::TAG_SIZE;
    static constexpr std::size_t SIGNATURE_SIZE = Ed25519::SIGNATURE_SIZE;
    static constexpr std::size_t STAMP_SIZE = sizeof(std::uint64_t);
    static constexpr std::size_t MAX_PLAINTEXT = 4096;

    // 签名消息的长度上限：stamp ‖ nonce ‖ cipher ‖ tag
    static constexpr std::size_t MAX_SIGNED_MESSAGE =
        STAMP_SIZE + NONCE_SIZE + MAX_PLAINTEXT + TAG_SIZE;

    SignedEnvelope() noexcept = default;
    SignedEnvelope(const SignedEnvelope&) = delete;
    SignedEnvelope& operator=(const SignedEnvelope&) = delete;

    // 配置服务端的 Ed25519 公钥。未配置时 open 一律失败。
    bool set_verifier_key_hex(const char* public_key_hex) noexcept {
        return verifier_.set_public_key_hex(public_key_hex);
    }

    bool verifier_loaded() const noexcept { return verifier_.loaded(); }

    struct Wire {
        std::uint64_t issued_at;
        const std::uint8_t* nonce;
        const std::uint8_t* cipher;
        std::size_t cipher_length;
        const std::uint8_t* tag;
        const std::uint8_t* signature;
    };

    // 打开信封，返回明文长度。
    //
    // 失败返回 0，且不留下任何输出字节。用长度而非布尔作为返回值的
    // 理由：调用方拿到 0 就用不了，即使有人把返回值改成非零，解出的
    // 也是被擦除过的缓冲区。授权载荷至少 24 字节，因此 0 不会与合法
    // 结果混淆。
    //
    // max_age_ms 为 0 表示不做年龄检查。非零时拒绝 now_ms 与 issued_at
    // 相差超过该值的信封，用于抵御重放。时钟超前一律拒绝。
    std::size_t open(const Wire& wire,
                     const void* card_key, std::size_t card_key_len,
                     const void* evidence, std::size_t evidence_len,
                     std::uint8_t domain,
                     std::uint64_t now_ms,
                     std::uint64_t max_age_ms,
                     std::uint8_t* out, std::size_t out_capacity) noexcept {
        if (!verifier_.loaded())
            return 0;
        if (wire.nonce == nullptr || wire.tag == nullptr ||
            wire.signature == nullptr || out == nullptr)
            return 0;
        if (wire.cipher == nullptr && wire.cipher_length != 0)
            return 0;
        if (wire.cipher_length == 0 || wire.cipher_length > MAX_PLAINTEXT)
            return 0;
        if (out_capacity < wire.cipher_length)
            return 0;

        // 签名覆盖信封全部字节
        std::uint8_t message[MAX_SIGNED_MESSAGE];
        std::size_t message_len = 0;
        detail::store_le64(message, wire.issued_at);
        message_len += STAMP_SIZE;
        for (std::size_t i = 0; i < NONCE_SIZE; ++i)
            message[message_len++] = wire.nonce[i];
        for (std::size_t i = 0; i < wire.cipher_length; ++i)
            message[message_len++] = wire.cipher[i];
        for (std::size_t i = 0; i < TAG_SIZE; ++i)
            message[message_len++] = wire.tag[i];

        const bool authentic = verifier_.verify(message, message_len,
                                                wire.signature, SIGNATURE_SIZE);
        detail::secure_wipe(message, message_len);
        if (!authentic)
            return 0;

        if (max_age_ms != 0) {
            if (wire.issued_at > now_ms)
                return 0;
            if (now_ms - wire.issued_at > max_age_ms)
                return 0;
        }

        std::uint8_t session_key[evidence::Binder::KEY_SIZE];
        if (!evidence::Binder::derive(card_key, card_key_len,
                                      wire.nonce, NONCE_SIZE,
                                      evidence, evidence_len, domain,
                                      session_key)) {
            detail::secure_wipe(session_key, sizeof(session_key));
            return 0;
        }

        // nonce、issued_at 与 domain 作为附加认证数据，与签名互为补充
        std::uint8_t aad[STAMP_SIZE + NONCE_SIZE + 1];
        std::size_t aad_len = 0;
        detail::store_le64(aad, wire.issued_at);
        aad_len += STAMP_SIZE;
        for (std::size_t i = 0; i < NONCE_SIZE; ++i)
            aad[aad_len++] = wire.nonce[i];
        aad[aad_len++] = domain;

        Aes256Gcm cipher;
        cipher.set_key(session_key);

        const bool opened = cipher.decrypt(wire.nonce, wire.cipher,
                                           wire.cipher_length, wire.tag,
                                           aad, aad_len, out);

        detail::secure_wipe(session_key, sizeof(session_key));
        detail::secure_wipe(aad, sizeof(aad));

        if (!opened) {
            detail::secure_wipe(out, wire.cipher_length);
            return 0;
        }

        return wire.cipher_length;
    }

private:
    Ed25519 verifier_;
};

}  // namespace veil::license
