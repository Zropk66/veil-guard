#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"
#include "../json_scan.hpp"
#include "../license/signed_envelope.hpp"
#include "cert_pin.hpp"
#include "http.hpp"
#include "tls_client.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::transport {

// 授权接口客户端。
//
// 把一次验证拆成可独立测试的三段：构造请求、收发、解析响应。三段都
// 由调用方驱动，任何一段都可以替换或跳过，因此没有内嵌的重试、没有
// 后台线程、没有全局状态。
//
// 服务端响应中的信封以 JSON 字符串传输。这里不把响应解析成对象再
// 重新序列化——服务端签名覆盖的是 JSON.stringify 产出的精确字节，
// 重新编码会让键序与转义与 Node 不一致，验签永久失败。信封的十六
// 进制字段因此直接用 JsonScanner 在原始文本上取区间。
class LicenseClient {
public:
    static constexpr std::size_t MAX_RESPONSE = HttpResponse::MAX_BODY;

    struct Request {
        const char* host;
        const char* path;
        const void* body;
        std::size_t body_length;
    };

    struct Response {
        std::uint32_t status;
        std::size_t length;
    };

    LicenseClient() noexcept = default;
    ~LicenseClient() noexcept { close(); }

    LicenseClient(const LicenseClient&) = delete;
    LicenseClient& operator=(const LicenseClient&) = delete;

    bool connect(const char* host, std::uint16_t port,
                 const CertPin& pin) noexcept {
        return tls_.connect_to(host, port, pin);
    }

    bool connected() const noexcept { return tls_.connected(); }

    void close() noexcept { tls_.close(); }

    // 对端证书公钥指纹。接入方据此校验 pin 是否仍与预期一致。
    const std::uint8_t* peer_digest() const noexcept {
        return tls_.peer_digest();
    }

    // 发送请求并读回完整响应。返回 false 表示传输失败、响应头非法或
    // 消息体超出缓冲区。响应文本不含任何东西时同样返回 false。
    bool exchange(const Request& request, char* out, std::size_t capacity,
                  Response* response) noexcept {
        if (out == nullptr || capacity < 2)
            return false;
        if (!tls_.connected())
            return false;

        char head[512];
        const std::size_t head_length = HttpRequest::build_post(
            request.host, request.path, request.body_length, head,
            sizeof(head));
        if (head_length == 0)
            return false;

        if (!tls_.send(head, head_length))
            return false;
        if (request.body_length > 0)
            if (!tls_.send(request.body, request.body_length))
                return false;

        return read_response(out, capacity, response);
    }

private:
    bool read_response(char* out, std::size_t capacity,
                       Response* response) noexcept {
        // 头部长度不固定，且可能在任意一次读取的中途被截断，因此
        // 逐块读入直到出现空行为止，不能假设一次读够。
        std::size_t filled = 0;
        std::size_t head_end = 0;

        HttpResponse parsed;
        bool head_ok = false;

        while (filled < capacity) {
            const std::size_t want =
                (capacity - filled) < CHUNK ? (capacity - filled) : CHUNK;
            if (!tls_.recv(out + filled, want))
                break;

            filled += want;

            const std::size_t terminator = find_head_end(out, filled);
            if (terminator == 0)
                continue;

            head_end = terminator;
            if (!parsed.parse_head(out, head_end))
                return false;
            head_ok = true;
            break;
        }

        if (!head_ok)
            return false;

        if (response != nullptr) {
            response->status = parsed.status();
            response->length = 0;
        }

        const std::size_t body_begin = head_end;
        std::size_t available = filled - body_begin;
        std::size_t body_length = 0;

        if (parsed.chunked()) {
            // 分块体需要完整读入才能解码，长度未知，按块续读
            while (filled < capacity) {
                const std::size_t want = (capacity - filled) < CHUNK
                                             ? (capacity - filled)
                                             : CHUNK;
                if (!tls_.recv(out + filled, want))
                    break;
                filled += want;
            }

            available = filled - body_begin;
            std::uint8_t decoded[MAX_RESPONSE];
            std::size_t decoded_length = 0;
            if (!HttpResponse::decode_chunked(out + body_begin, available,
                                              decoded, sizeof(decoded),
                                              &decoded_length))
                return false;
            if (decoded_length > capacity - 1)
                return false;

            for (std::size_t i = 0; i < decoded_length; ++i)
                out[i] = static_cast<char>(decoded[i]);
            body_length = decoded_length;
        } else if (parsed.has_content_length()) {
            const std::size_t needed = parsed.content_length();
            if (needed > capacity - 1)
                return false;

            while (available < needed && filled < capacity) {
                const std::size_t want = (capacity - filled) < CHUNK
                                             ? (capacity - filled)
                                             : CHUNK;
                if (!tls_.recv(out + filled, want))
                    break;
                filled += want;
                available = filled - body_begin;
            }

            if (available < needed)
                return false;

            for (std::size_t i = 0; i < needed; ++i)
                out[i] = out[body_begin + i];
            body_length = needed;
        } else {
            // 无长度声明：读到连接关闭为止，已读入的部分即为消息体
            while (filled < capacity) {
                const std::size_t want = (capacity - filled) < CHUNK
                                             ? (capacity - filled)
                                             : CHUNK;
                if (!tls_.recv(out + filled, want))
                    break;
                filled += want;
            }

            for (std::size_t i = 0; i < available; ++i)
                out[i] = out[body_begin + i];
            body_length = available;
        }

        if (body_length == 0)
            return false;

        out[body_length] = '\0';
        if (response != nullptr)
            response->length = body_length;
        return true;
    }

    // 定位头部结束位置：空行的下一个字节。返回 0 表示尚未读到。
    static std::size_t find_head_end(const char* text,
                                     std::size_t length) noexcept {
        for (std::size_t i = 0; i + 1 < length; ++i) {
            if (i + 3 < length && text[i] == '\r' && text[i + 1] == '\n' &&
                text[i + 2] == '\r' && text[i + 3] == '\n')
                return i + 4;
            if (text[i] == '\n' && text[i + 1] == '\n')
                return i + 2;
        }
        return 0;
    }

    static constexpr std::size_t CHUNK = 4096;

    TlsClient tls_;
};

}  // namespace veil::transport
