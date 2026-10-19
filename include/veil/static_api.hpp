#pragma once

#include "config.hpp"
#include "evidence/binder.hpp"

#include <cstddef>
#include <cstdint>

// 静态库形态的入口。
//
// 这些符号的实现体只存在于 veil::static 内，消费方的翻译单元里
// 只有声明。相比 header-only 形态，调用点不再携带观测采集与 HKDF
// 展开的机器码，派生链的字节序列无法在调用方一侧被就地改写。
//
// 使用本头文件时必须链接 veil::static，否则符号未定义。
extern "C" {

// 采集一组标准观测并序列化为证据 blob。观测顺序由库固定，
// 调用方无法指定。written 返回写入的字节数。
bool veil_capture_standard_evidence(std::uint8_t* out, std::size_t capacity,
                                    std::size_t* written) noexcept;

// 以调用方提供的证据派生会话密钥。
bool veil_derive_session_key(const void* card_key, std::size_t card_key_len,
                             const void* nonce, std::size_t nonce_len,
                             const void* evidence, std::size_t evidence_len,
                             std::uint8_t domain, std::uint8_t* out,
                             std::size_t out_len) noexcept;

// 采集标准证据并直接派生，不把证据暴露给调用方。
//
// 静态库形态下的推荐入口：证据字节不经过调用方的内存，调用方只
// 拿到会话密钥，无法观察也无法改写派生所用的 info。
bool veil_derive_from_environment(const void* card_key,
                                  std::size_t card_key_len,
                                  const void* nonce, std::size_t nonce_len,
                                  std::uint8_t domain, std::uint8_t* out,
                                  std::size_t out_len) noexcept;

// 采集含代码完整性观测的证据，对应服务端登记表里的布局 2。
//
// 与标准布局的区别是多出 260 字节的磁盘-内存摘要差值，正常环境下
// 全零，因此服务端仍用零基线复现，不需要登记每版哈希。
//
// 不可在 DllMain 中调用：采集会打开自身映像文件，而加载器锁在模块
// 初始化期间被持有，此时做文件操作会死锁。推迟到首次派生时机。
//
// failures 返回本次采集中摘要失败的区域数。非零不构成拒绝理由——
// 失败区域的槽位保持零，与未篡改环境的观测相同。可用于记录，但不应
// 据此做授权判定。
bool veil_capture_integrity_evidence(std::uint8_t* out, std::size_t capacity,
                                     std::size_t* written,
                                     std::size_t* failures) noexcept;

// 以布局 2 采集并直接派生。参数与服务端登记表里的布局 2 对应。
bool veil_derive_with_integrity(const void* card_key, std::size_t card_key_len,
                                const void* nonce, std::size_t nonce_len,
                                std::uint8_t domain, std::uint8_t* out,
                                std::size_t out_len) noexcept;

}  // extern "C"
