#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"
#include "cert_pin.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#include <wincrypt.h>
#include <ws2tcpip.h>

namespace veil::transport {

// Schannel TLS 客户端。
//
// 指纹比对与链校验是两条独立防线：链校验由 Schannel 完成，指纹
// 在其后叠加。不使用 ISC_REQ_MANUAL_CRED_VALIDATION，避免为锁定
// 指纹而放弃标准链校验。
//
// 握手循环必须按 SECBUFFER_EXTRA 处理剩余字节。TLS 1.3 下服务端
// 通常把整条飞行放在同一趟发出，每次只读一条记录会丢弃同趟的其余
// 字节，导致后续解析错位。此处的处理是把未消费部分搬回缓冲区头部
// 留待下一轮。
class TlsClient {
public:
    static constexpr std::size_t MAX_RECORD = 16u * 1024u;

    TlsClient() noexcept = default;
    ~TlsClient() noexcept { close(); }

    TlsClient(const TlsClient&) = delete;
    TlsClient& operator=(const TlsClient&) = delete;

    bool connect_to(const char* host, std::uint16_t port,
                    const CertPin& pin) noexcept {
        if (host == nullptr)
            return false;
        if (connected())
            return false;

        if (!open_socket(host, port))
            return false;
        if (!acquire_credentials())
            return false;
        if (!perform_handshake(host, pin))
            return false;

        return true;
    }

    bool connected() const noexcept { return handshake_done_; }

    // 对端证书公钥指纹的实测值。未完成握手时为零值。
    const std::uint8_t* peer_digest() const noexcept { return peer_digest_; }

    void close() noexcept {
        if (context_valid_) {
            if (handshake_done_) {
                SecBuffer shutdown{};
                shutdown.BufferType = SECBUFFER_TOKEN;
                shutdown.cbBuffer = 0;
                shutdown.pvBuffer = nullptr;

                SecBufferDesc shutdown_desc{};
                shutdown_desc.ulVersion = SECBUFFER_VERSION;
                shutdown_desc.cBuffers = 1;
                shutdown_desc.pBuffers = &shutdown;

                DWORD shutdown_flags = 0;
                ApplyControlToken(&context_, &shutdown_desc);
                (void)shutdown_flags;
            }
            DeleteSecurityContext(&context_);
            context_valid_ = false;
        }
        if (credentials_valid_) {
            FreeCredentialsHandle(&credentials_);
            credentials_valid_ = false;
        }
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
        if (wsa_started_) {
            WSACleanup();
            wsa_started_ = false;
        }
        handshake_done_ = false;
        veil::detail::secure_wipe(peer_digest_, sizeof(peer_digest_));
    }

private:
    bool open_socket(const char* host, std::uint16_t port) noexcept {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return false;
        wsa_started_ = true;

        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        char service[8];
        service[0] = static_cast<char>('0' + (port / 10000) % 10);
        service[1] = static_cast<char>('0' + (port / 1000) % 10);
        service[2] = static_cast<char>('0' + (port / 100) % 10);
        service[3] = static_cast<char>('0' + (port / 10) % 10);
        service[4] = static_cast<char>('0' + port % 10);
        service[5] = '\0';

        addrinfo* resolved = nullptr;
        if (getaddrinfo(host, service, &hints, &resolved) != 0)
            return false;

        for (addrinfo* it = resolved; it != nullptr; it = it->ai_next) {
            socket_ = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if (socket_ == INVALID_SOCKET)
                continue;
            if (::connect(socket_, it->ai_addr,
                          static_cast<int>(it->ai_addrlen)) == 0)
                break;
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }

        freeaddrinfo(resolved);
        return socket_ != INVALID_SOCKET;
    }

    bool acquire_credentials() noexcept {
        SCHANNEL_CRED cred{};
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT |
                                     SP_PROT_TLS1_3_CLIENT;
        cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION |
                       SCH_CRED_NO_DEFAULT_CREDS;

        TimeStamp expiry{};
        const SECURITY_STATUS status = AcquireCredentialsHandleA(
            nullptr, const_cast<char*>(UNISP_NAME_A), SECPKG_CRED_OUTBOUND,
            nullptr, &cred, nullptr, nullptr, &credentials_, &expiry);

        credentials_valid_ = status == SEC_E_OK;
        return credentials_valid_;
    }

    bool perform_handshake(const char* host, const CertPin& pin) noexcept {
        SecBuffer in_buffers[2]{};
        in_buffers[0].BufferType = SECBUFFER_TOKEN;
        in_buffers[0].pvBuffer = nullptr;
        in_buffers[0].cbBuffer = 0;
        // Schannel 要求输入缓冲区中保留一个额外的空 SECBUFFER_TOKEN，
        // 用于承载握手各趟之间的剩余数据。
        in_buffers[1].BufferType = SECBUFFER_EMPTY;
        in_buffers[1].pvBuffer = nullptr;
        in_buffers[1].cbBuffer = 0;

        SecBufferDesc in_desc{};
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 2;
        in_desc.pBuffers = in_buffers;

        // 输入缓冲区的后备存储，跨轮次复用
        std::uint8_t incoming[MAX_RECORD];
        std::size_t incoming_size = 0;

        DWORD requested = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                          ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                          ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

        for (int round = 0; round < 16; ++round) {
            SecBuffer out_buffers[1]{};
            out_buffers[0].BufferType = SECBUFFER_TOKEN;
            out_buffers[0].pvBuffer = nullptr;
            out_buffers[0].cbBuffer = 0;

            SecBufferDesc out_desc{};
            out_desc.ulVersion = SECBUFFER_VERSION;
            out_desc.cBuffers = 1;
            out_desc.pBuffers = out_buffers;

            DWORD flags = requested;
            TimeStamp expiry{};
            const SECURITY_STATUS status = InitializeSecurityContextA(
                &credentials_, context_valid_ ? &context_ : nullptr,
                const_cast<char*>(host),
                requested, 0, SECURITY_NATIVE_DREP, &in_desc, 0,
                &context_, &out_desc, &flags, &expiry);

            if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
                context_valid_ = true;
                if (out_buffers[0].cbBuffer > 0)
                    if (!send_all(out_buffers[0].pvBuffer,
                                  out_buffers[0].cbBuffer))
                        return false;
                if (out_buffers[0].pvBuffer != nullptr)
                    FreeContextBuffer(out_buffers[0].pvBuffer);
            } else {
                return false;
            }

            if (status == SEC_E_OK) {
                handshake_done_ = true;
                break;
            }

            // 上一轮遗留的剩余字节必须留在输入缓冲区中
            incoming_size = carry_over(in_buffers, incoming, incoming_size);

            if (!receive_more(incoming, &incoming_size))
                return false;

            in_buffers[0].pvBuffer = incoming;
            in_buffers[0].cbBuffer = static_cast<unsigned long>(incoming_size);
            in_buffers[1].BufferType = SECBUFFER_EMPTY;
            in_buffers[1].pvBuffer = nullptr;
            in_buffers[1].cbBuffer = 0;

            if (!inspect_peer_certificate(pin))
                return false;
        }

        if (!handshake_done_)
            return false;

        return inspect_peer_certificate(pin);
    }

    // 把上一轮未消费的字节搬回缓冲区头部。
    static std::size_t carry_over(const SecBuffer in_buffers[2],
                                  std::uint8_t* incoming,
                                  std::size_t incoming_size) noexcept {
        for (std::size_t i = 0; i < 2; ++i) {
            if (in_buffers[i].BufferType != SECBUFFER_EXTRA ||
                in_buffers[i].cbBuffer == 0)
                continue;

            const std::size_t extra = in_buffers[i].cbBuffer;
            const auto* source = static_cast<const std::uint8_t*>(
                in_buffers[i].pvBuffer != nullptr
                    ? in_buffers[i].pvBuffer
                    : incoming + (incoming_size - extra));

            if (source != incoming)
                for (std::size_t k = 0; k < extra; ++k)
                    incoming[k] = source[k];

            return extra;
        }
        return 0;
    }

    bool receive_more(std::uint8_t* buffer, std::size_t* size) noexcept {
        if (buffer == nullptr || size == nullptr)
            return false;
        if (*size >= MAX_RECORD)
            return false;

        const int received = recv(socket_,
                                  reinterpret_cast<char*>(buffer + *size),
                                  static_cast<int>(MAX_RECORD - *size), 0);
        if (received <= 0)
            return false;

        *size += static_cast<std::size_t>(received);
        return true;
    }

    bool send_all(const void* data, std::size_t size) noexcept {
        const auto* bytes = static_cast<const char*>(data);
        std::size_t sent = 0;
        while (sent < size) {
            const int written = send(socket_, bytes + sent,
                                     static_cast<int>(size - sent), 0);
            if (written <= 0)
                return false;
            sent += static_cast<std::size_t>(written);
        }
        return true;
    }

    // 取对端证书的 SubjectPublicKeyInfo 摘要，并按 pin 判定是否继续。
    //
    // 该函数只在握手过程中被调用。指纹不符即断开，没有降级路径：
    // 这是传输层唯一的判定点，且它判定的是「服务端是不是它声称的
    // 那个服务端」，而不是本地环境是否被篡改。
    bool inspect_peer_certificate(const CertPin& pin) noexcept {
        PCCERT_CONTEXT peer = nullptr;
        const SECURITY_STATUS status = QueryContextAttributesA(
            &context_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer);
        if (status != SEC_E_OK || peer == nullptr)
            return true;  // 尚未收到证书，下一轮再取

        const bool digested = detail::spki_digest(peer, peer_digest_);
        CertFreeCertificateContext(peer);

        if (!digested)
            return false;

        if (!pin.configured())
            return true;

        return veil::detail::constant_time_compare(peer_digest_, pin.digest(),
                                             CertPin::DIGEST_SIZE) == 1;
    }

    SOCKET socket_ = INVALID_SOCKET;
    CredHandle credentials_{};
    CtxtHandle context_{};
    bool credentials_valid_ = false;
    bool context_valid_ = false;
    bool handshake_done_ = false;
    bool wsa_started_ = false;
    std::uint8_t peer_digest_[CertPin::DIGEST_SIZE]{};
};

}  // namespace veil::transport
