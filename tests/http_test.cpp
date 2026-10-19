#include <veil/transport/http.hpp>
#include "support/test_main.hpp"

#include <cstring>

namespace {

std::size_t len(const char* text) { return std::strlen(text); }

}  // namespace

int main() {
    using namespace veil;
    using namespace veil::transport;

    // 定长响应
    {
        const char* raw =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 17\r\n"
            "\r\n"
            "{\"success\":true}\n";
        HttpResponse response;
        test::expect(response.parse_head(raw, len(raw)),
                     "parses a fixed length response head");
        test::expect(response.status() == 200, "reports the status code");
        test::expect(response.has_content_length(), "finds the length field");
        test::expect(response.content_length() == 17, "reads the length value");
        test::expect(!response.chunked(), "fixed length is not chunked");
        test::expect(response.body_offset() ==
                         len("HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/json\r\n"
                             "Content-Length: 17\r\n"
                             "\r\n"),
                     "reports the body offset");
    }

    // 分块响应
    {
        const char* raw =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        HttpResponse response;
        test::expect(response.parse_head(raw, len(raw)),
                     "parses a chunked response head");
        test::expect(response.chunked(), "detects chunked encoding");
        test::expect(!response.has_content_length(),
                     "chunked response has no length field");

        std::uint8_t decoded[64];
        std::size_t written = 0;
        test::expect(HttpResponse::decode_chunked(
                         raw + response.body_offset(),
                         len(raw) - response.body_offset(), decoded,
                         sizeof(decoded), &written),
                     "decodes the chunked body");
        test::expect(written == 11, "decoded length spans both chunks");
        test::expect(std::memcmp(decoded, "hello world", 11) == 0,
                     "decoded bytes concatenate the chunks");
    }

    // 状态码解析
    {
        const char* raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        HttpResponse response;
        test::expect(response.parse_head(raw, len(raw)), "parses a 404 head");
        test::expect(response.status() == 404, "reports the 404 status");
    }

    // 不带 CR 的裸 LF 响应
    {
        const char* raw = "HTTP/1.1 200 OK\nContent-Length: 2\n\nok";
        HttpResponse response;
        test::expect(response.parse_head(raw, len(raw)),
                     "accepts bare line feeds");
        test::expect(response.status() == 200, "parses the bare LF status");
        test::expect(response.content_length() == 2, "parses the bare LF length");
    }

    // 非法输入
    {
        HttpResponse response;

        const char* bad_version = "HTTP/2 200 OK\r\n\r\n";
        test::expect(!response.parse_head(bad_version, len(bad_version)),
                     "rejects a non HTTP/1.x version");

        const char* bad_status = "HTTP/1.1 99 X\r\n\r\n";
        test::expect(!response.parse_head(bad_status, len(bad_status)),
                     "rejects a three digit status outside the range");

        const char* no_colon = "HTTP/1.1 200 OK\r\nBrokenHeader\r\n\r\n";
        test::expect(!response.parse_head(no_colon, len(no_colon)),
                     "rejects a header without a colon");

        const char* folded = "HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n";
        test::expect(!response.parse_head(folded, len(folded)),
                     "rejects an obsolete folded header");

        test::expect(!response.parse_head(nullptr, 10),
                     "rejects a null response");
        test::expect(!response.parse_head("", 0), "rejects an empty response");

        const char* truncated = "HTTP/1.1 200 OK";
        test::expect(!response.parse_head(truncated, len(truncated)),
                     "rejects a head with no terminator");
    }

    // 长度字段非法
    {
        HttpResponse response;
        const char* negative = "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n";
        test::expect(!response.parse_head(negative, len(negative)),
                     "rejects a negative length");

        const char* huge =
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n";
        test::expect(!response.parse_head(huge, len(huge)),
                     "rejects a length above the bound");

        const char* conflict =
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        test::expect(!response.parse_head(conflict, len(conflict)),
                     "rejects conflicting length fields");
    }

    // 分块体非法
    {
        std::uint8_t out[64];
        std::size_t written = 0;

        const char* bad_hex = "zz\r\nhello\r\n0\r\n\r\n";
        test::expect(!HttpResponse::decode_chunked(bad_hex, len(bad_hex), out,
                                                   sizeof(out), &written),
                     "rejects a chunk without a hex length");

        const char* no_crlf = "5\r\nhelloX";
        test::expect(!HttpResponse::decode_chunked(no_crlf, len(no_crlf), out,
                                                   sizeof(out), &written),
                     "rejects a chunk missing its terminator");

        const char* short_data = "5\r\nhel\r\n0\r\n\r\n";
        test::expect(!HttpResponse::decode_chunked(short_data, len(short_data),
                                                   out, sizeof(out), &written),
                     "rejects a chunk shorter than its declared size");

        const char* no_final = "5\r\nhello\r\n";
        test::expect(!HttpResponse::decode_chunked(no_final, len(no_final), out,
                                                   sizeof(out), &written),
                     "rejects a body with no terminating chunk");

        std::uint8_t small[4];
        const char* too_big = "5\r\nhello\r\n0\r\n\r\n";
        test::expect(!HttpResponse::decode_chunked(too_big, len(too_big), small,
                                                   sizeof(small), &written),
                     "rejects a body exceeding the output buffer");
    }

    // 请求构造
    {
        char out[512];
        const std::size_t written =
            HttpRequest::build_post("license.example.com", "/api/verify", 17,
                                    out, sizeof(out));
        test::expect(written > 0, "builds a post request");
        out[written] = '\0';

        test::expect(std::strstr(out, "POST /api/verify HTTP/1.1\r\n") == out,
                     "request starts with the method and path");
        test::expect(std::strstr(out, "Host: license.example.com\r\n") != nullptr,
                     "request carries the host header");
        test::expect(std::strstr(out, "Content-Length: 17\r\n") != nullptr,
                     "request declares the body length");
        test::expect(std::strstr(out, "\r\n\r\n") != nullptr,
                     "request head ends with a blank line");

        // 缓冲区不足必须整体失败，不能写出半截请求
        char tight[16];
        test::expect(HttpRequest::build_post("host", "/p", 1, tight,
                                              sizeof(tight)) == 0,
                     "rejects an undersized request buffer");

        test::expect(HttpRequest::build_post(nullptr, "/p", 1, out,
                                              sizeof(out)) == 0,
                     "rejects a null host");
        test::expect(HttpRequest::build_post("h", nullptr, 1, out,
                                              sizeof(out)) == 0,
                     "rejects a null path");
        test::expect(HttpRequest::build_post("h", "/p",
                                              HttpRequest::MAX_BODY + 1, out,
                                              sizeof(out)) == 0,
                     "rejects a body above the bound");
    }

    return test::finish("http");
}
