#pragma once

#include "config.hpp"
#include "detail/common.hpp"

#include <cstddef>
#include <cstdint>

namespace veil {

// 原始 JSON 文本的区间扫描。
//
// 服务端签名覆盖 JSON.stringify 产出的精确字节。客户端若把解密结果
// 解析成对象再重新序列化，键序、数字格式与 Unicode 转义都可能与 Node
// 不一致，导致验签永久失败。因此这里直接在原始文本上定位值区间，
// 不做任何重编码。
//
// 与常规 JSON 解析器的区别：不构造语法树、不解释值、不校验 schema。
// 它只回答一个问题——这个键对应的原始字节在哪个区间。
class JsonScanner {
public:
    struct Span {
        const char* begin;
        std::size_t length;
    };

    JsonScanner(const char* text, std::size_t length) noexcept
        : text_(text), length_(length) {}

    // 定位顶层对象中指定键对应的完整值区间。返回的区间包含引号、
    // 括号与嵌套结构，即 JSON.stringify 输出的原样字节。
    //
    // 命中后仍继续校验剩余成员与闭合括号。若在闭合前返回，截断的
    // 文本会被当作合法输入，定位到一个不完整的区间——而验签用的
    // 正是这个区间，误差会直接传到签名校验上。
    bool find_top_level(const char* key, Span* out) const noexcept {
        if (text_ == nullptr || key == nullptr || out == nullptr)
            return false;

        std::size_t cursor = 0;
        skip_whitespace(cursor);

        if (cursor >= length_ || text_[cursor] != '{')
            return false;
        ++cursor;

        const std::size_t key_length = str_length(key);

        // 命中位置先记下，等整个对象确认闭合后再对外返回
        bool found = false;
        std::size_t found_begin = 0;
        std::size_t found_length = 0;

        while (true) {
            skip_whitespace(cursor);
            if (cursor >= length_)
                return false;
            if (text_[cursor] == '}')
                break;
            if (text_[cursor] != '"')
                return false;

            const std::size_t name_begin = cursor + 1;
            if (!skip_string(cursor))
                return false;
            const std::size_t name_length = cursor - 1 - name_begin;

            skip_whitespace(cursor);
            if (cursor >= length_ || text_[cursor] != ':')
                return false;
            ++cursor;
            skip_whitespace(cursor);

            const std::size_t value_begin = cursor;
            if (!skip_value(cursor))
                return false;
            const std::size_t value_length = cursor - value_begin;

            if (!found && name_length == key_length &&
                detail::constant_time_compare(text_ + name_begin, key,
                                              key_length) == 1) {
                found = true;
                found_begin = value_begin;
                found_length = value_length;
            }

            skip_whitespace(cursor);
            if (cursor >= length_)
                return false;
            if (text_[cursor] == ',') {
                ++cursor;
                continue;
            }
            if (text_[cursor] == '}') {
                ++cursor;
                break;
            }
            return false;
        }

        if (!found)
            return false;

        out->begin = text_ + found_begin;
        out->length = found_length;
        return true;
    }

    // 读取键的字符串值，剥去外层引号。仅用于 error / message 一类
    // 简单字段；需要参与验签的字段一律用 find_top_level 取原始区间。
    bool find_string(const char* key, Span* out) const noexcept {
        if (out == nullptr)
            return false;

        Span span{};
        if (!find_top_level(key, &span))
            return false;
        if (span.length < 2 || span.begin[0] != '"')
            return false;

        out->begin = span.begin + 1;
        out->length = span.length - 2;
        return true;
    }

    // 读取键的整数。返回 false 表示值不是整数或超出可精确表示的
    // 范围。溢出即拒绝，避免时间戳被静默截断成错误值。
    bool find_integer(const char* key, std::int64_t* out) const noexcept {
        if (out == nullptr)
            return false;

        Span span{};
        if (!find_top_level(key, &span) || span.length == 0)
            return false;

        std::size_t index = 0;
        bool negative = false;
        if (span.begin[index] == '-') {
            negative = true;
            ++index;
        }
        if (index >= span.length)
            return false;

        std::int64_t value = 0;
        bool saw_digit = false;

        for (; index < span.length; ++index) {
            const char c = span.begin[index];
            if (c == '.' || c == 'e' || c == 'E')
                return false;
            if (c < '0' || c > '9')
                return false;
            if (value > (INT64_MAX - (c - '0')) / 10)
                return false;

            value = value * 10 + (c - '0');
            saw_digit = true;
        }

        if (!saw_digit)
            return false;

        *out = negative ? -value : value;
        return true;
    }

private:
    static std::size_t str_length(const char* text) noexcept {
        std::size_t length = 0;
        while (text[length] != '\0')
            ++length;
        return length;
    }

    void skip_whitespace(std::size_t& cursor) const noexcept {
        while (cursor < length_) {
            const char c = text_[cursor];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
                break;
            ++cursor;
        }
    }

    // 跳过被引号包裹的字符串，正确识别反斜杠转义，使内容中的
    // 引号不会提前终止扫描。
    bool skip_string(std::size_t& cursor) const noexcept {
        if (cursor >= length_ || text_[cursor] != '"')
            return false;
        ++cursor;

        while (cursor < length_) {
            const char c = text_[cursor];
            if (c == '\\') {
                cursor += 2;
                continue;
            }
            if (c == '"') {
                ++cursor;
                return true;
            }
            ++cursor;
        }
        return false;
    }

    bool skip_value(std::size_t& cursor) const noexcept {
        if (cursor >= length_)
            return false;

        const char c = text_[cursor];
        if (c == '"')
            return skip_string(cursor);
        if (c == '{' || c == '[')
            return skip_container(cursor);
        return skip_literal(cursor);
    }

    bool skip_container(std::size_t& cursor) const noexcept {
        const char open = text_[cursor];
        const char close = (open == '{') ? '}' : ']';
        const bool is_object = (open == '{');
        ++cursor;

        while (true) {
            skip_whitespace(cursor);
            if (cursor >= length_)
                return false;

            const char c = text_[cursor];
            if (c == close) {
                ++cursor;
                return true;
            }

            if (c == '"') {
                if (!skip_string(cursor))
                    return false;

                // 对象成员的键之后必须跟随冒号，数组元素则不会出现
                // 冒号。漏掉这一步会让后续解析从冒号开始，整段结构
                // 判定失准。
                if (is_object) {
                    skip_whitespace(cursor);
                    if (cursor >= length_ || text_[cursor] != ':')
                        return false;
                    ++cursor;
                    skip_whitespace(cursor);
                    if (!skip_value(cursor))
                        return false;
                }
            } else if (c == '{' || c == '[') {
                if (!skip_container(cursor))
                    return false;
            } else if (!skip_literal(cursor)) {
                return false;
            }

            skip_whitespace(cursor);
            if (cursor >= length_)
                return false;

            if (text_[cursor] == ',') {
                ++cursor;
                continue;
            }
            if (text_[cursor] == close) {
                ++cursor;
                return true;
            }
            return false;
        }
    }

    // 处理 true / false / null / 数字，均以非结构字符作为终止条件。
    bool skip_literal(std::size_t& cursor) const noexcept {
        const std::size_t begin = cursor;
        while (cursor < length_) {
            const char c = text_[cursor];
            if (c == ',' || c == '}' || c == ']' || c == ' ' ||
                c == '\t' || c == '\n' || c == '\r')
                break;
            ++cursor;
        }
        return cursor > begin;
    }

    const char* text_;
    std::size_t length_;
};

}  // namespace veil
