#include <veil/detail/common.hpp>
#include <veil/json_scan.hpp>
#include "support/test_main.hpp"

#include <cstring>
#include <fstream>
#include <string>

namespace {

std::string read_all(const char* path) {
    std::ifstream in(path);
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
}

// 把 JSON 字符串字面量的内容还原成实际字节。Node 写出的期望值里
// 引号与反斜杠是转义形式，直接比对会差一层。
std::string unescape(const char* text, std::size_t length) {
    std::string out;
    for (std::size_t i = 0; i < length; ++i) {
        if (text[i] != '\\' || i + 1 >= length) {
            out.push_back(text[i]);
            continue;
        }

        const char next = text[i + 1];
        switch (next) {
            case '"': out.push_back('"'); ++i; break;
            case '\\': out.push_back('\\'); ++i; break;
            case '/': out.push_back('/'); ++i; break;
            case 'n': out.push_back('\n'); ++i; break;
            case 't': out.push_back('\t'); ++i; break;
            case 'r': out.push_back('\r'); ++i; break;
            case 'u':
                // 非 BMP 转义按原样保留，夹具中不涉及
                out.append(text + i, 6);
                i += 5;
                break;
            default: out.push_back(next); ++i; break;
        }
    }
    return out;
}

}  // namespace

int main() {
    using namespace veil;

    const std::string payload = read_all("tests/fixtures/json_payload.txt");
    const std::string envelope = read_all("tests/fixtures/json_envelope.txt");
    const std::string expected_raw = read_all("tests/fixtures/json_expected.json");

    test::expect(!payload.empty(), "loads the signed payload fixture");
    test::expect(!envelope.empty(), "loads the envelope fixture");
    test::expect(!expected_raw.empty(), "loads the expected value fixture");
    if (payload.empty() || envelope.empty() || expected_raw.empty())
        return test::finish("json_vectors");

    JsonScanner payload_scanner(payload.data(), payload.size());

    // expected 是夹具里的嵌套对象，键在第二层，先取出整块再在其中扫描
    JsonScanner expected_root(expected_raw.data(), expected_raw.size());
    JsonScanner::Span expected_block{};
    test::expect(expected_root.find_top_level("expected", &expected_block),
                 "locates the expected value block");
    if (expected_block.begin == nullptr)
        return test::finish("json_vectors");

    JsonScanner expected_scanner(expected_block.begin, expected_block.length);

    // 逐键比对：定位到的区间必须与 Node 的 JSON.stringify 产出逐字节相同。
    // 键序刻意打乱，覆盖 JSON.stringify 保留插入顺序这一性质。
    const char* keys[] = {"zeta", "alpha", "nested", "unicode",
                          "large", "empty", "list"};

    for (const char* key : keys) {
        JsonScanner::Span located{};
        if (!payload_scanner.find_top_level(key, &located)) {
            test::expect(false, key);
            continue;
        }

        JsonScanner::Span quoted{};
        if (!expected_scanner.find_string(key, &quoted)) {
            test::expect(false, key);
            continue;
        }

        const std::string target = unescape(quoted.begin, quoted.length);

        const bool same = located.length == target.size() &&
                          std::memcmp(located.begin, target.data(),
                                      target.size()) == 0;
        test::expect(same, key);
    }

    // 键序必须与插入顺序一致，而不是字典序
    {
        JsonScanner::Span zeta{};
        JsonScanner::Span alpha{};
        payload_scanner.find_top_level("zeta", &zeta);
        payload_scanner.find_top_level("alpha", &alpha);
        test::expect(zeta.begin < alpha.begin,
                     "key order follows insertion order, not lexical order");
    }

    // 整数精度：夹具中的大整数仍在 JS 安全范围内，必须精确读出
    {
        std::int64_t value = 0;
        test::expect(payload_scanner.find_integer("large", &value),
                     "reads the large integer from the payload");
        test::expect(value == 9007199254740991LL,
                     "large integer survives the round trip");

        test::expect(payload_scanner.find_integer("zeta", &value) && value == 1,
                     "small integer is exact");
    }

    // 非整数键必须拒绝
    {
        std::int64_t value = 0;
        test::expect(!payload_scanner.find_integer("nested", &value),
                     "object is not an integer");
        test::expect(!payload_scanner.find_integer("alpha", &value),
                     "string is not an integer");
    }

    // 信封层：data 在内部是转义过的字符串，其原始区间必须带引号
    {
        JsonScanner envelope_scanner(envelope.data(), envelope.size());

        JsonScanner::Span raw{};
        test::expect(envelope_scanner.find_top_level("data", &raw),
                     "locates data as a raw span in the envelope");
        test::expect(raw.length > 2 && raw.begin[0] == '"' &&
                         raw.begin[raw.length - 1] == '"',
                     "raw data span keeps its quotes");

        JsonScanner::Span sig{};
        test::expect(envelope_scanner.find_string("sig", &sig),
                     "reads the signature from the envelope");
        test::expect(sig.length == 4 && std::memcmp(sig.begin, "cafe", 4) == 0,
                     "signature content is preserved");

        std::int64_t code = 0;
        test::expect(envelope_scanner.find_integer("code", &code) && code == 0,
                     "reads the envelope status code");
    }

    // 转义还原后信封内的 data 内容必须与独立夹具逐字节一致，
    // 这验证了「签名覆盖原始字节」这条约定的自洽性
    {
        JsonScanner envelope_scanner(envelope.data(), envelope.size());
        JsonScanner::Span quoted{};
        envelope_scanner.find_string("data", &quoted);

        const std::string restored = unescape(quoted.begin, quoted.length);
        test::expect(restored.size() == payload.size() &&
                         std::memcmp(restored.data(), payload.data(),
                                     payload.size()) == 0,
                     "envelope data round trips to the standalone payload");
    }

    return test::finish("json_vectors");
}
