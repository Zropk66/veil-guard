#include "veil/guard.hpp"
#include "veil/evidence/layout.hpp"
#include "veil/providers/anti_debug.hpp"
#include "veil/providers/cert_pin.hpp"
#include "veil/providers/code_integrity.hpp"
#include "veil/providers/module_topo.hpp"

namespace veil {

// 标准证据布局：AntiDebugSnapshot 16 + ModuleTopology 20 + CertificatePin 32。
//
// 这个长度是对外契约。服务端用零基线按同一长度构造 info，因此客户端
// 改动 provider 顺序或增删 provider 后，服务端必须同步，否则全部客户端
// 派生分叉。静态断言在编译期锁定，避免改动后静默失配。
using StandardLayout = evidence::Layout<providers::AntiDebugSnapshot,
                                        providers::ModuleTopology,
                                        providers::CertificatePin>;

static_assert(StandardLayout::SIZE == STANDARD_EVIDENCE_SIZE,
              "the standard evidence layout changed; the server must be updated");

// 含代码完整性 provider 的布局。服务端登记为布局 2。
//
// CodeIntegrity 带实例状态，需在采集前完成区域登记，因此它的布局
// 由调用方自行装配，不在此处固定。这里只锁定长度契约。
using IntegrityLayout = evidence::Layout<providers::AntiDebugSnapshot,
                                         providers::ModuleTopology,
                                         providers::CertificatePin,
                                         providers::CodeIntegrity>;

static_assert(IntegrityLayout::SIZE == INTEGRITY_EVIDENCE_SIZE,
              "the integrity layout changed; the server registry must be updated");

// 静态库形态的实现单元。
//
// 与 header-only 的区别不在行为，而在可见性：这些实现体编译进库后
// 消费方只看到声明，无法在自己的翻译单元里替换它们。header-only
// 形态下全部实现随头文件展开，任何一处都可被就地改写。
//
// 因此这里只承载「改写后收益最大」的几项：环境观测采集与会话派生。
// 密码学与平台层保持 header 内联，它们的正确性靠测试向量锁定，
// 不需要隐藏。

// 采集一组标准观测并序列化为证据 blob。
//
// 观测顺序在此固定。消费方改动顺序或增删 provider，服务端必须同步，
// 否则派生分叉——这正是设计意图，顺序因此不能由调用方指定。
extern "C" bool veil_capture_standard_evidence(std::uint8_t* out,
                                               std::size_t capacity,
                                               std::size_t* written) noexcept {
    if (out == nullptr || written == nullptr)
        return false;

    if (capacity < StandardLayout::SIZE)
        return false;

    const providers::AntiDebugSnapshot debug_probe;
    const providers::ModuleTopology topo_probe;
    const providers::CertificatePin pin_probe;

    if (!StandardLayout::serialize(out, capacity, debug_probe, topo_probe,
                                   pin_probe))
        return false;

    *written = StandardLayout::SIZE;
    return true;
}

// 以证据为 info 派生会话密钥。封装成独立符号后，调用点不再携带
// HKDF 的展开代码，派生链的字节序列只存在于库内部。
extern "C" bool veil_derive_session_key(const void* card_key,
                                        std::size_t card_key_len,
                                        const void* nonce,
                                        std::size_t nonce_len,
                                        const void* evidence,
                                        std::size_t evidence_len,
                                        std::uint8_t domain,
                                        std::uint8_t* out,
                                        std::size_t out_len) noexcept {
    if (out == nullptr || out_len < evidence::Binder::KEY_SIZE)
        return false;

    return evidence::Binder::derive(card_key, card_key_len, nonce, nonce_len,
                                    evidence, evidence_len, domain, out);
}

// 采集标准证据并直接派生，不把证据暴露给调用方。
//
// 这是静态库形态下的推荐入口：证据字节不经过调用方的内存，调用方
// 只拿到会话密钥，无法观察也无法改写派生所用的 info。
extern "C" bool veil_derive_from_environment(const void* card_key,
                                             std::size_t card_key_len,
                                             const void* nonce,
                                             std::size_t nonce_len,
                                             std::uint8_t domain,
                                             std::uint8_t* out,
                                             std::size_t out_len) noexcept {
    if (out == nullptr || out_len < evidence::Binder::KEY_SIZE)
        return false;

    std::uint8_t evidence_buffer[MAX_EVIDENCE_BYTES];
    std::size_t written = 0;

    const bool captured = veil_capture_standard_evidence(
        evidence_buffer, sizeof(evidence_buffer), &written);

    bool derived = false;
    if (captured)
        derived = evidence::Binder::derive(card_key, card_key_len, nonce,
                                           nonce_len, evidence_buffer, written,
                                           domain, out);

    detail::secure_wipe(evidence_buffer, sizeof(evidence_buffer));
    return derived;
}

// 采集含代码完整性观测的证据，对应服务端登记表里的布局 2。
//
// 与标准布局的区别是多出 260 字节的磁盘-内存摘要差值。正常环境下这些
// 差值为零，因此服务端仍用零基线复现，不需要登记每版哈希。
//
// 调用前提：不可在 DllMain 中调用。register_module_sections 会打开自身
// 映像文件，而加载器锁在模块初始化期间被持有，此时做文件操作会死锁。
// 推迟到首次派生的时机，与 Guard 的约定一致。
//
// failures 返回本次采集中摘要失败的区域数。非零不构成拒绝理由——失败
// 的区域槽位保持零，与未篡改环境的观测相同。调用方可以据此记录，但
// 不应以此做授权判定。
extern "C" bool veil_capture_integrity_evidence(std::uint8_t* out,
                                                std::size_t capacity,
                                                std::size_t* written,
                                                std::size_t* failures) noexcept {
    if (out == nullptr || written == nullptr)
        return false;

    if (capacity < IntegrityLayout::SIZE)
        return false;

    providers::CodeIntegrity integrity_probe;

    if (failures != nullptr)
        *failures = 0;

    // 磁盘映像不可读时不应中断采集。摘要失败的槽位保持零，与正常环境
    // 无法区分，因此采集本身仍然成功——这正是「不提供判定点」的要求。
    const bool registered = integrity_probe.register_module_sections();
    if (!registered && failures != nullptr) {
        // 未登记任何区域意味着差值槽位全零，布局仍然完整
        *failures = 1;
    }

    const providers::AntiDebugSnapshot debug_probe;
    const providers::ModuleTopology topo_probe;
    const providers::CertificatePin pin_probe;

    if (!IntegrityLayout::serialize(out, capacity, debug_probe, topo_probe,
                                    pin_probe, integrity_probe))
        return false;

    *written = IntegrityLayout::SIZE;
    return true;
}

// 以布局 2 采集并直接派生。参数与服务端登记表里的布局 2 对应。
extern "C" bool veil_derive_with_integrity(const void* card_key,
                                           std::size_t card_key_len,
                                           const void* nonce,
                                           std::size_t nonce_len,
                                           std::uint8_t domain,
                                           std::uint8_t* out,
                                           std::size_t out_len) noexcept {
    if (out == nullptr || out_len < evidence::Binder::KEY_SIZE)
        return false;

    std::uint8_t evidence_buffer[INTEGRITY_EVIDENCE_SIZE];
    std::size_t written = 0;

    const bool captured = veil_capture_integrity_evidence(
        evidence_buffer, sizeof(evidence_buffer), &written, nullptr);

    bool derived = false;
    if (captured)
        derived = evidence::Binder::derive(card_key, card_key_len, nonce,
                                           nonce_len, evidence_buffer, written,
                                           domain, out);

    detail::secure_wipe(evidence_buffer, sizeof(evidence_buffer));
    return derived;
}

}  // namespace veil
