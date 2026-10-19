#include <veil/detail/common.hpp>
#include <veil/json_scan.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    // 顶层键定位：区间必须包含完整原始字节，含引号与嵌套结构
    {
        const char text[] =
            "{\"code\":0,\"data\":{\"id\":42,\"name\":\"a\\\"b\"},\"sig\":\"00ff\"}";
        JsonScanner scanner(text, sizeof(text) - 1);

        JsonScanner::Span span{};
        test::expect(scanner.find_top_level("data", &span),
                     "locates a nested object value");
        test::expect(span.length == 23, "nested value spans the exact bytes");
        test::expect(std::strncmp(span.begin, "{\"id\":42,\"name\":\"a\\\"b\"}", 23) == 0,
                     "nested value is returned verbatim");

        test::expect(scanner.find_top_level("sig", &span),
                     "locates a trailing key");
        test::expect(span.length == 6, "string value spans the quoted bytes");
        test::expect(std::strncmp(span.begin, "\"00ff\"", 6) == 0,
                     "string value keeps its quotes");

        test::expect(scanner.find_top_level("code", &span),
                     "locates a numeric value");
        test::expect(span.length == 1 && span.begin[0] == '0',
                     "numeric value is returned raw");

        test::expect(!scanner.find_top_level("absent", &span),
                     "absent key is not found");
    }

    // 字符串值剥引号
    {
        const char text[] = "{\"error\":\"not found\"}";
        JsonScanner scanner(text, sizeof(text) - 1);

        JsonScanner::Span span{};
        test::expect(scanner.find_string("error", &span),
                     "reads a string value");
        test::expect(span.length == 9, "string excludes the surrounding quotes");
        test::expect(std::strncmp(span.begin, "not found", 9) == 0,
                     "string content is preserved");
    }

    // 整数读取
    {
        const char text[] =
            "{\"issuedAt\":1700000000000,\"expiresAt\":0,\"negative\":-7}";
        JsonScanner scanner(text, sizeof(text) - 1);

        std::int64_t value = 0;
        test::expect(scanner.find_integer("issuedAt", &value),
                     "reads a large integer");
        test::expect(value == 1700000000000LL, "large integer is exact");

        test::expect(scanner.find_integer("expiresAt", &value),
                     "reads zero");
        test::expect(value == 0, "zero is read as zero");

        test::expect(scanner.find_integer("negative", &value),
                     "reads a negative integer");
        test::expect(value == -7, "negative value keeps its sign");
    }

    // 越界整数必须拒绝而不是截断
    {
        const char text[] = "{\"big\":99999999999999999999}";
        JsonScanner scanner(text, sizeof(text) - 1);

        std::int64_t value = 0;
        test::expect(!scanner.find_integer("big", &value),
                     "overlong integer is rejected");
    }

    // 非整数必须拒绝
    {
        const char text[] = "{\"f\":1.5,\"e\":1e3,\"s\":\"x\"}";
        JsonScanner scanner(text, sizeof(text) - 1);

        std::int64_t value = 0;
        test::expect(!scanner.find_integer("f", &value), "decimal is rejected");
        test::expect(!scanner.find_integer("e", &value), "exponent is rejected");
        test::expect(!scanner.find_integer("s", &value), "string is rejected");
    }

    // 数组、字面量与深层嵌套
    {
        const char text[] =
            "{\"a\":[1,2,{\"b\":[true,null]},3],\"c\":false,\"d\":null}";
        JsonScanner scanner(text, sizeof(text) - 1);

        JsonScanner::Span span{};
        test::expect(scanner.find_top_level("a", &span),
                     "locates an array value");
        test::expect(span.begin[0] == '[' && span.begin[span.length - 1] == ']',
                     "array value keeps its brackets");

        test::expect(scanner.find_top_level("c", &span), "locates false");
        test::expect(span.length == 5 && span.begin[0] == 'f',
                     "false is returned raw");

        test::expect(scanner.find_top_level("d", &span), "locates null");
        test::expect(span.length == 4 && span.begin[0] == 'n',
                     "null is returned raw");
    }

    // 键名是另一键名后缀时不得误命中
    {
        const char text[] = "{\"id\":1,\"userId\":2}";
        JsonScanner scanner(text, sizeof(text) - 1);

        JsonScanner::Span span{};
        test::expect(scanner.find_top_level("id", &span), "locates the short key");
        test::expect(span.begin[0] == '1', "short key does not match a suffix");
    }

    // 空白与换行
    {
        const char text[] =
            "{\n  \"a\" : 1 ,\n  \"b\" : \"two\"\n}";
        JsonScanner scanner(text, sizeof(text) - 1);

        JsonScanner::Span span{};
        test::expect(scanner.find_top_level("b", &span),
                     "tolerates whitespace around separators");
        test::expect(std::strncmp(span.begin, "\"two\"", 5) == 0,
                     "value bytes exclude surrounding whitespace");
    }

    // 格式错误的输入必须拒绝
    {
        const char text[] = "{\"a\":1";
        JsonScanner scanner(text, sizeof(text) - 1);
        JsonScanner::Span span{};
        test::expect(!scanner.find_top_level("a", &span),
                     "truncated object is rejected");
    }
    {
        const char text[] = "[1,2,3]";
        JsonScanner scanner(text, sizeof(text) - 1);
        JsonScanner::Span span{};
        test::expect(!scanner.find_top_level("a", &span),
                     "top level array is rejected");
    }
    {
        const char text[] = "{\"a\" 1}";
        JsonScanner scanner(text, sizeof(text) - 1);
        JsonScanner::Span span{};
        test::expect(!scanner.find_top_level("a", &span),
                     "missing colon is rejected");
    }
    {
        const char text[] = "{\"a\":\"unterminated}";
        JsonScanner scanner(text, sizeof(text) - 1);
        JsonScanner::Span span{};
        test::expect(!scanner.find_top_level("a", &span),
                     "unterminated string is rejected");
    }

    // 输入校验
    {
        JsonScanner scanner("{}", 2);
        JsonScanner::Span span{};
        test::expect(!scanner.find_top_level(nullptr, &span),
                     "null key is rejected");
        test::expect(!scanner.find_top_level("a", nullptr),
                     "null output is rejected");

        JsonScanner empty(nullptr, 0);
        test::expect(!empty.find_top_level("a", &span),
                     "null text is rejected");

        std::int64_t value = 0;
        JsonScanner scanner2("{\"a\":1}", 7);
        test::expect(!scanner2.find_integer("a", nullptr),
                     "null integer output is rejected");
        test::expect(scanner2.find_integer("a", &value) && value == 1,
                     "integer output is filled when provided");
    }

    // 空对象
    {
        const char text[] = "{}";
        JsonScanner scanner(text, sizeof(text) - 1);
        JsonScanner::Span span{};
        test::expect(!scanner.find_top_level("a", &span),
                     "empty object yields no key");
    }

    return test::finish("json_scan");
}
