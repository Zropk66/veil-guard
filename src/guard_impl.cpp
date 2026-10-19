#include "veil/guard.hpp"
#include "veil/evidence/layout.hpp"
#include "veil/providers/anti_debug.hpp"
#include "veil/providers/cert_pin.hpp"
#include "veil/providers/module_topo.hpp"

namespace veil {

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

    using Layout = evidence::Layout<providers::AntiDebugSnapshot,
                                    providers::ModuleTopology,
                                    providers::CertificatePin>;

    if (capacity < Layout::SIZE)
        return false;

    const providers::AntiDebugSnapshot debug_probe;
    const providers::ModuleTopology topo_probe;
    const providers::CertificatePin pin_probe;

    if (!Layout::serialize(out, capacity, debug_probe, topo_probe, pin_probe))
        return false;

    *written = Layout::SIZE;
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

}  // namespace veil
