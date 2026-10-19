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

    // 发送应用数据。返回 false 表示未连接、参数非法或对端已关闭。
    //
    // 单条 TLS 记录的上限由 Schannel 在握手后给出，超出部分自动分片。
    // 分片对调用方透明：一次调用可以跨越任意条记录。
    bool send(const void* data, std::size_t size) noexcept {
        if (!handshake_done_ || data == nullptr || size == 0)
            return false;

        const auto* bytes = static_cast<const std::uint8_t*>(data);
        while (size > 0) {
            const std::size_t chunk =
                size < max_message_ ? size : max_message_;

            // 记录布局为 header ‖ data ‖ trailer，三段连成一块连续内存
            if (header_size_ + chunk + trailer_size_ > MAX_RECORD * 2)
                return false;

            std::uint8_t record[MAX_RECORD * 2];
            for (std::size_t i = 0; i < chunk; ++i)
                record[header_size_ + i] = bytes[i];

            SecBuffer buffers[4]{};
            buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
            buffers[0].pvBuffer = record;
            buffers[0].cbBuffer = static_cast<unsigned long>(header_size_);
            buffers[1].BufferType = SECBUFFER_DATA;
            buffers[1].pvBuffer = record + header_size_;
            buffers[1].cbBuffer = static_cast<unsigned long>(chunk);
            buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
            buffers[2].pvBuffer = record + header_size_ + chunk;
            buffers[2].cbBuffer = static_cast<unsigned long>(trailer_size_);
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc desc{};
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = buffers;

            if (EncryptMessage(&context_, 0, &desc, 0) != SEC_E_OK)
                return false;

            const std::size_t total = buffers[0].cbBuffer +
                                      buffers[1].cbBuffer +
                                      buffers[2].cbBuffer;
            if (!send_raw(record, total))
                return false;

            bytes += chunk;
            size -= chunk;
        }
        return true;
    }

    // 接收指定字节数的应用数据。
    //
    // 一条 TLS 记录可能只含部分所需字节，一次读取也可能带来多条记录
    // 的明文。因此跨调用的剩余明文必须由实例持有，不能用线程级静态
    // 缓冲——同一线程上的两个客户端会互相覆盖对方的残留数据。
    bool recv(void* buffer, std::size_t size) noexcept {
        if (!handshake_done_ || buffer == nullptr || size == 0)
            return false;

        auto* out = static_cast<std::uint8_t*>(buffer);
        std::size_t filled = 0;

        while (filled < size) {
            if (pending_offset_ < pending_length_) {
                const std::size_t available = pending_length_ - pending_offset_;
                const std::size_t take = (size - filled < available)
                                             ? (size - filled)
                                             : available;
                for (std::size_t i = 0; i < take; ++i)
                    out[filled + i] = pending_[pending_offset_ + i];
                pending_offset_ += take;
                filled += take;
                continue;
            }

            pending_length_ = 0;
            pending_offset_ = 0;

            std::uint8_t record[MAX_RECORD * 2];

            // TLS 记录头固定五字节：类型、版本两字节、长度两字节
            if (!recv_raw(record, 5))
                return false;

            const std::size_t payload =
                (static_cast<std::size_t>(record[3]) << 8) | record[4];
            if (payload == 0 || payload + 5 > sizeof(record))
                return false;

            if (!recv_raw(record + 5, payload))
                return false;

            SecBuffer buffers[4]{};
            buffers[0].BufferType = SECBUFFER_DATA;
            buffers[0].pvBuffer = record;
            buffers[0].cbBuffer = static_cast<unsigned long>(payload + 5);
            buffers[1].BufferType = SECBUFFER_EMPTY;
            buffers[2].BufferType = SECBUFFER_EMPTY;
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc desc{};
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = buffers;

            const SECURITY_STATUS status =
                DecryptMessage(&context_, &desc, 0, nullptr);

            // 会话结束与重新协商都不是业务数据，直接拒绝
            if (status != SEC_E_OK)
                return false;

            for (std::size_t i = 0; i < 4; ++i) {
                if (buffers[i].BufferType != SECBUFFER_DATA ||
                    buffers[i].cbBuffer == 0)
                    continue;

                const std::size_t length = buffers[i].cbBuffer;
                if (length > sizeof(pending_))
                    return false;

                const auto* source =
                    static_cast<const std::uint8_t*>(buffers[i].pvBuffer);
                for (std::size_t k = 0; k < length; ++k)
                    pending_[k] = source[k];
                pending_length_ = length;
                pending_offset_ = 0;
            }
        }

        return true;
    }

    // 已解密但尚未被调用方取走的字节数。
    std::size_t pending_bytes() const noexcept {
        return pending_length_ - pending_offset_;
    }

    void close() noexcept {
        if (context_valid_) {
            if (handshake_done_)
                send_close_notify();
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
        pending_length_ = 0;
        pending_offset_ = 0;
        header_size_ = 0;
        trailer_size_ = 0;
        max_message_ = 0;
        veil::detail::secure_wipe(peer_digest_, sizeof(peer_digest_));
    }

private:
    // 发送 TLS 关闭告警。
    //
    // 不发这一步时对端看到的是连接被直接断开，而非有序关闭。某些
    // 服务端与中间设备会把这种情况记为异常，重连策略也会不同。
    void send_close_notify() noexcept {
        SecBuffer shutdown{};
        shutdown.BufferType = SECBUFFER_TOKEN;
        shutdown.cbBuffer = 0;
        shutdown.pvBuffer = nullptr;

        SecBufferDesc desc{};
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 1;
        desc.pBuffers = &shutdown;

        if (ApplyControlToken(&context_, &desc) != SEC_E_OK)
            return;

        SecBuffer out{};
        out.BufferType = SECBUFFER_TOKEN;
        out.cbBuffer = 0;
        out.pvBuffer = nullptr;

        SecBufferDesc out_desc{};
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = &out;

        DWORD flags = 0;
        TimeStamp expiry{};
        if (InitializeSecurityContextA(&credentials_, &context_, nullptr, 0, 0,
                                       SECURITY_NATIVE_DREP, nullptr, 0,
                                       nullptr, &out_desc, &flags,
                                       &expiry) != SEC_E_OK)
            return;

        if (out.cbBuffer > 0 && out.pvBuffer != nullptr) {
            send_raw(out.pvBuffer, out.cbBuffer);
            FreeContextBuffer(out.pvBuffer);
        }
    }

    // 查询 Schannel 给出的记录布局参数。三段尺寸由安全包决定，
    // 硬编码会在换加密套件时失配。
    bool query_stream_sizes() noexcept {
        SecPkgContext_StreamSizes sizes{};
        if (QueryContextAttributesA(&context_, SECPKG_ATTR_STREAM_SIZES,
                                    &sizes) != SEC_E_OK)
            return false;

        header_size_ = sizes.cbHeader;
        trailer_size_ = sizes.cbTrailer;
        max_message_ = sizes.cbMaximumMessage;

        return header_size_ > 0 && max_message_ > 0;
    }

    bool send_raw(const void* data, std::size_t size) noexcept {
        const auto* bytes = static_cast<const char*>(data);
        std::size_t sent = 0;
        while (sent < size) {
            const int written = ::send(socket_, bytes + sent,
                                       static_cast<int>(size - sent), 0);
            if (written <= 0)
                return false;
            sent += static_cast<std::size_t>(written);
        }
        return true;
    }

    bool recv_raw(void* data, std::size_t size) noexcept {
        auto* bytes = static_cast<char*>(data);
        std::size_t received = 0;
        while (received < size) {
            const int read = ::recv(socket_, bytes + received,
                                    static_cast<int>(size - received), 0);
            if (read <= 0)
                return false;
            received += static_cast<std::size_t>(read);
        }
        return true;
    }

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

        if (!query_stream_sizes())
            return false;

        // 指纹不符时握手本身已经完成，但连接不得对外表现为可用。
        // 不清掉状态会让调用方在 connect_to 失败后仍看到 connected()
        // 为真，进而把数据发往一个已被判定的对端。
        if (!inspect_peer_certificate(pin)) {
            handshake_done_ = false;
            return false;
        }

        return true;
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

        const int received = ::recv(socket_,
                                    reinterpret_cast<char*>(buffer + *size),
                                    static_cast<int>(MAX_RECORD - *size), 0);
        if (received <= 0)
            return false;

        *size += static_cast<std::size_t>(received);
        return true;
    }

    bool send_all(const void* data, std::size_t size) noexcept {
        return send_raw(data, size);
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

    std::size_t header_size_ = 0;
    std::size_t trailer_size_ = 0;
    std::size_t max_message_ = 0;

    // 跨调用的已解密明文。置于实例内而非线程静态，避免同一线程上的
    // 两个客户端互相覆盖残留数据。
    std::uint8_t pending_[MAX_RECORD * 2]{};
    std::size_t pending_length_ = 0;
    std::size_t pending_offset_ = 0;
};

}  // namespace veil::transport
