#pragma once

#include "../config.hpp"
#include "../crypto/sha256.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#include <wincrypt.h>

namespace veil::transport {

// 对端证书公钥指纹。
//
// 取 SubjectPublicKeyInfo 而非整张证书：证书续期时公钥不变，
// 指纹因此跨续期稳定，不必每次换证书都重新发版。
//
// 链校验仍由 Schannel 完成，指纹比对其后叠加。不使用
// ISC_REQ_MANUAL_CRED_VALIDATION，避免为锁定指纹而放弃标准链校验。
class CertPin {
public:
    static constexpr std::size_t DIGEST_SIZE = 32;

    CertPin() noexcept = default;

    explicit CertPin(const std::uint8_t digest[DIGEST_SIZE]) noexcept {
        set(digest);
    }

    void set(const std::uint8_t digest[DIGEST_SIZE]) noexcept {
        configured_ = digest != nullptr;
        for (std::size_t i = 0; i < DIGEST_SIZE; ++i)
            digest_[i] = digest != nullptr ? digest[i] : 0;
    }

    bool configured() const noexcept { return configured_; }

    const std::uint8_t* digest() const noexcept { return digest_; }

    ~CertPin() noexcept { detail::secure_wipe(digest_, sizeof(digest_)); }

private:
    std::uint8_t digest_[DIGEST_SIZE]{};
    bool configured_ = false;
};

namespace detail {

// 从 CERT_CONTEXT 提取 SubjectPublicKeyInfo 的 DER 编码并求摘要。
//
// X509_PUBLIC_KEY_INFO 内是两段独立指针加长度，直接按结构体求哈希
// 会读到无关数据，必须先经 CryptEncodeObjectEx 编码回 DER。
//
// CRYPT_ENCODE_ALLOC_FLAG 下不能先用空指针探测所需长度：该调用会
// 试图写入空地址并触发访问违规。必须一次调用直接分配。
inline bool spki_digest(PCCERT_CONTEXT certificate,
                        std::uint8_t out[CertPin::DIGEST_SIZE]) noexcept {
    if (certificate == nullptr || out == nullptr)
        return false;

    BYTE* encoded = nullptr;
    DWORD encoded_size = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                             &certificate->pCertInfo->SubjectPublicKeyInfo,
                             CRYPT_ENCODE_ALLOC_FLAG, nullptr,
                             reinterpret_cast<void**>(&encoded),
                             &encoded_size))
        return false;

    if (encoded == nullptr || encoded_size == 0) {
        if (encoded != nullptr)
            LocalFree(encoded);
        return false;
    }

    Sha256::hash(encoded, encoded_size, out);

    LocalFree(encoded);
    return true;
}

}  // namespace detail

// 探测指定主机的证书公钥指纹。该入口不校验任何指纹，只供离线
// 密钥轮换工具调用，业务路径不得引用。
//
// 实现刻意保持最小：完成一次 TCP 连接与 TLS 握手，取对端证书求
// 指纹后立即断开，不发送任何应用数据。
bool probe_pin(const char* host, std::uint16_t port,
               std::uint8_t out[CertPin::DIGEST_SIZE]) noexcept;

}  // namespace veil::transport
