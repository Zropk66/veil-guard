#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::transport {

// HTTP/1.1 响应解析。
//
// 只处理服务端返回的定长与分块两种传输编码，不做重定向、不做连接
// 复用、不解析分块扩展。对接自家服务端足够，语义也收得更紧：任何
// 形态超出预期即拒绝，不给宽松解析留下的错位空间。
//
// 响应头必须在独立的缓冲区里解析后，把消息体交给调用方。直接在原
// 缓冲区上就地解析会让超长头字段的边界判断变得依赖实现细节。
class HttpResponse {
public:
    static constexpr std::size_t MAX_HEADER = 8u * 1024u;
    static constexpr std::size_t MAX_BODY = 256u * 1024u;

    // 解析响应头。传入的文本以空行结束，返回消息体的起始偏移。
    // 同时给出状态码与两种传输编码的元信息。
    bool parse_head(const char* text, std::size_t length) noexcept {
        status_ = 0;
        content_length_ = 0;
        has_content_length_ = false;
        chunked_ = false;
        body_offset_ = 0;

        if (text == nullptr || length == 0 || length > MAX_HEADER)
            return false;

        // 状态行形如 HTTP/1.1 200 OK
        std::size_t cursor = 0;
        if (!match_literal(text, length, cursor, "HTTP/1."))
            return false;
        if (cursor >= length ||
            (text[cursor] != '0' && text[cursor] != '1'))
            return false;
        ++cursor;
        if (cursor >= length || text[cursor] != ' ')
            return false;
        ++cursor;

        if (cursor + 3 > length)
            return false;
        if (text[cursor] < '0' || text[cursor] > '9')
            return false;

        status_ = static_cast<std::uint32_t>(text[cursor] - '0') * 100;
        status_ += static_cast<std::uint32_t>(text[cursor + 1] - '0') * 10;
        status_ += static_cast<std::uint32_t>(text[cursor + 2] - '0');
        cursor += 3;

        if (status_ < 100 || status_ > 599)
            return false;

        // 跳过状态行剩余部分
        while (cursor < length && text[cursor] != '\n')
            ++cursor;
        if (cursor >= length)
            return false;
        ++cursor;

        // 逐条头字段
        while (cursor < length) {
            if (text[cursor] == '\n') {
                body_offset_ = cursor + 1;
                return true;
            }
            if (text[cursor] == '\r') {
                if (cursor + 1 >= length || text[cursor + 1] != '\n')
                    return false;
                body_offset_ = cursor + 2;
                return true;
            }

            const std::size_t line_begin = cursor;
            while (cursor < length && text[cursor] != '\n')
                ++cursor;
            if (cursor >= length)
                return false;

            std::size_t line_end = cursor;
            if (line_end > line_begin && text[line_end - 1] == '\r')
                --line_end;
            ++cursor;

            if (!parse_field(text, line_begin, line_end))
                return false;
        }

        return false;
    }

    std::uint32_t status() const noexcept { return status_; }
    std::size_t body_offset() const noexcept { return body_offset_; }
    bool has_content_length() const noexcept { return has_content_length_; }
    std::size_t content_length() const noexcept { return content_length_; }
    bool chunked() const noexcept { return chunked_; }

    // 把分块消息体解成连续字节。
    //
    // 每块形如「十六进制长度 CRLF 数据 CRLF」，以长度 0 的块收尾。
    // 收尾块之后可能有 trailer，此处忽略——调用方拿到完整消息体即
    // 可停止，无需读完 trailer。
    static bool decode_chunked(const char* text, std::size_t length,
                               std::uint8_t* out, std::size_t capacity,
                               std::size_t* written) noexcept {
        if (text == nullptr || out == nullptr || written == nullptr)
            return false;

        *written = 0;
        std::size_t cursor = 0;

        while (true) {
            const std::size_t size = parse_hex_line(text, length, cursor);
            if (size == BAD_HEX)
                return false;

            if (size == 0) {
                // 收尾块：至少要跟一个 CRLF，之后可选的 trailer 不再读
                if (cursor + 1 >= length)
                    return false;
                if (text[cursor] != '\r' || text[cursor + 1] != '\n')
                    return false;
                return true;
            }

            if (cursor + size > length)
                return false;
            if (*written + size > capacity)
                return false;

            for (std::size_t i = 0; i < size; ++i)
                out[*written + i] = static_cast<std::uint8_t>(text[cursor + i]);
            *written += size;
            cursor += size;

            if (cursor + 1 >= length)
                return false;
            if (text[cursor] != '\r' || text[cursor + 1] != '\n')
                return false;
            cursor += 2;
        }
    }

private:
    static constexpr std::size_t BAD_HEX = static_cast<std::size_t>(-1);

    static bool match_literal(const char* text, std::size_t length,
                              std::size_t& cursor, const char* literal) noexcept {
        std::size_t i = 0;
        while (literal[i] != '\0') {
            if (cursor + i >= length || text[cursor + i] != literal[i])
                return false;
            ++i;
        }
        cursor += i;
        return true;
    }

    static char lower(char c) noexcept {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
    }

    bool parse_field(const char* text, std::size_t begin,
                     std::size_t end) noexcept {
        if (begin >= end)
            return false;

        // 折叠续行在 HTTP/1.1 中已废弃，出现即拒绝
        if (text[begin] == ' ' || text[begin] == '\t')
            return false;

        std::size_t colon = begin;
        while (colon < end && text[colon] != ':')
            ++colon;
        if (colon >= end)
            return false;

        const std::size_t name_end = colon;
        ++colon;
        while (colon < end && (text[colon] == ' ' || text[colon] == '\t'))
            ++colon;

        if (name_equals(text, begin, name_end, "content-length")) {
            std::size_t value = 0;
            if (!parse_decimal(text, colon, end, &value))
                return false;
            if (has_content_length_ && value != content_length_)
                return false;  // 冲突的长度声明
            content_length_ = value;
            has_content_length_ = true;
            return value <= MAX_BODY;
        }

        if (name_equals(text, begin, name_end, "transfer-encoding")) {
            if (token_equals(text, colon, end, "chunked"))
                chunked_ = true;
            return true;
        }

        return true;
    }

    static bool name_equals(const char* text, std::size_t begin,
                            std::size_t end, const char* name) noexcept {
        std::size_t i = 0;
        while (name[i] != '\0') {
            if (begin + i >= end || lower(text[begin + i]) != name[i])
                return false;
            ++i;
        }
        return begin + i == end;
    }

    static bool token_equals(const char* text, std::size_t begin,
                             std::size_t end, const char* token) noexcept {
        std::size_t i = 0;
        while (begin + i < end &&
               (text[begin + i] == ' ' || text[begin + i] == '\t'))
            ++i;
        const std::size_t start = begin + i;
        std::size_t k = 0;
        while (token[k] != '\0') {
            if (start + k >= end || lower(text[start + k]) != token[k])
                return false;
            ++k;
        }
        std::size_t tail = start + k;
        while (tail < end && (text[tail] == ' ' || text[tail] == '\t'))
            ++tail;
        return tail == end;
    }

    static bool parse_decimal(const char* text, std::size_t begin,
                              std::size_t end, std::size_t* out) noexcept {
        if (begin >= end)
            return false;

        std::size_t value = 0;
        bool digit = false;
        for (std::size_t i = begin; i < end; ++i) {
            const char c = text[i];
            if (c == ' ' || c == '\t')
                continue;
            if (c < '0' || c > '9')
                return false;
            if (value > (MAX_BODY + 1 - static_cast<std::size_t>(c - '0')) / 10)
                return false;
            value = value * 10 + static_cast<std::size_t>(c - '0');
            digit = true;
        }

        if (!digit)
            return false;
        *out = value;
        return true;
    }

    // 读一行十六进制长度并推进 cursor 越过该行的 CRLF
    static std::size_t parse_hex_line(const char* text, std::size_t length,
                                      std::size_t& cursor) noexcept {
        std::size_t value = 0;
        bool digit = false;

        while (cursor < length) {
            const char c = text[cursor];
            if (c == '\r' || c == '\n')
                break;

            int nibble = -1;
            if (c >= '0' && c <= '9') nibble = c - '0';
            else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
            else break;  // 分块扩展，到此为止

            if (value > (MAX_BODY - static_cast<std::size_t>(nibble)) / 16)
                return BAD_HEX;
            value = value * 16 + static_cast<std::size_t>(nibble);
            digit = true;
            ++cursor;
        }

        if (!digit)
            return BAD_HEX;

        // 跳过块扩展
        while (cursor < length && text[cursor] != '\r' && text[cursor] != '\n')
            ++cursor;

        if (cursor + 1 >= length)
            return BAD_HEX;
        if (text[cursor] != '\r' || text[cursor + 1] != '\n')
            return BAD_HEX;
        cursor += 2;

        return value;
    }

    std::uint32_t status_ = 0;
    std::size_t body_offset_ = 0;
    std::size_t content_length_ = 0;
    bool has_content_length_ = false;
    bool chunked_ = false;
};

// HTTP/1.1 请求的头部构造。
//
// 只允许固定的方法与到服务端路径，调用方不构造任意头部。请求体由
// 调用方给出，长度以 Content-Length 声明：分块上传会引入一个额外
// 的状态机，而请求体已知长度，没有必要。
class HttpRequest {
public:
    static constexpr std::size_t MAX_BODY = 256u * 1024u;

    // 构造 POST 请求头。host 需与 TLS 层的 SNI 一致，否则 virtua
    // host 会路由到别的站点。返回写入长度，0 表示失败。
    static std::size_t build_post(const char* host, const char* path,
                                  std::size_t body_length, char* out,
                                  std::size_t capacity) noexcept {
        if (host == nullptr || path == nullptr || out == nullptr)
            return 0;
        if (body_length > MAX_BODY)
            return 0;

        std::size_t cursor = 0;
        if (!append(out, capacity, cursor, "POST "))
            return 0;
        if (!append(out, capacity, cursor, path))
            return 0;
        if (!append(out, capacity, cursor, " HTTP/1.1\r\nHost: "))
            return 0;
        if (!append(out, capacity, cursor, host))
            return 0;
        if (!append(out, capacity, cursor,
                    "\r\nContent-Type: application/json\r\n"
                    "Content-Length: "))
            return 0;
        if (!append_decimal(out, capacity, cursor, body_length))
            return 0;
        if (!append(out, capacity, cursor, "\r\nConnection: close\r\n\r\n"))
            return 0;

        return cursor;
    }

private:
    static bool append(char* out, std::size_t capacity, std::size_t& cursor,
                       const char* text) noexcept {
        std::size_t i = 0;
        while (text[i] != '\0') {
            if (cursor >= capacity)
                return false;
            out[cursor++] = text[i++];
        }
        return true;
    }

    static bool append_decimal(char* out, std::size_t capacity,
                               std::size_t& cursor,
                               std::size_t value) noexcept {
        char digits[24];
        std::size_t count = 0;
        if (value == 0)
            digits[count++] = '0';
        while (value > 0) {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        }
        while (count > 0) {
            if (cursor >= capacity)
                return false;
            out[cursor++] = digits[--count];
        }
        return true;
    }
};

}  // namespace veil::transport
