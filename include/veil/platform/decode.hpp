#pragma once

#include "../config.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::platform {

// x64 指令解码，只服务于一项任务：找出代码区间内的 RIP 相对寻址，
// 以便重映射时按位移修正。
//
// 重定位表不足以支撑重映射。同映像内部的引用不需要基址重定位，
// 因此表里没有它们的条目，但复制到新页后这些指令的 RIP 仍相对新页
// 计算，会指向错误地址。必须逐条解码才能找出这类引用。
//
// 不需要完整反汇编器。难点在于指令长度可变，必须正确解码每条指令
// 才能定位下一条的起点。未知编码按保守方式处理：整段停止修正，
// 由调用方决定是否继续。
class InstructionScanner {
public:
    struct RipReference {
        std::size_t offset;          // 指令在区间内的起始偏移
        std::size_t length;          // 指令总长度
        std::size_t disp_offset;     // 位移字段在区间内的偏移
        std::int64_t target_offset;  // 目标相对区间起点的偏移
    };

    // 逐条解码区间内的指令并回调所有 RIP 相对引用。
    // 遇到无法解码的字节即停止，返回已解码的字节数。
    template <typename Callback>
    static std::size_t scan(const std::uint8_t* code, std::size_t size,
                            Callback&& on_reference) noexcept {
        std::size_t cursor = 0;
        while (cursor < size) {
            const Decoded decoded = decode(code + cursor, size - cursor);
            if (decoded.length == 0)
                break;

            if (decoded.has_rip_reference) {
                RipReference reference{};
                reference.offset = cursor;
                reference.length = decoded.length;
                reference.disp_offset = cursor + decoded.disp_offset;
                // 解码是针对 code + cursor 进行的，目标偏移相对该点，
                // 换算回区间起点必须补上 cursor。
                reference.target_offset =
                    static_cast<std::int64_t>(cursor) + decoded.rip_target_offset;
                on_reference(reference);
            }

            cursor += decoded.length;
        }
        return cursor;
    }

private:
    struct Decoded {
        std::size_t length = 0;
        std::size_t disp_offset = 0;
        std::int64_t rip_target_offset = 0;
        bool has_rip_reference = false;
    };

    static bool is_prefix(std::uint8_t byte) noexcept {
        switch (byte) {
            case 0xF0:
            case 0xF2:
            case 0xF3:
            case 0x2E:
            case 0x36:
            case 0x3E:
            case 0x26:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
                return true;
            default:
                return false;
        }
    }

    // 判断该 opcode 是否携带 ModRM 字节。这是定位 RIP 相对寻址的
    // 前提：只有带 ModRM 的指令才可能编码 RIP 相对操作数。
    static bool has_modrm(std::uint8_t opcode) noexcept {
        if (opcode >= 0x40 && opcode <= 0x4F) return false;
        if (opcode >= 0x50 && opcode <= 0x5F) return false;
        if (opcode >= 0xB0 && opcode <= 0xBF) return false;

        switch (opcode) {
            case 0x90: case 0xC3: case 0xC9: case 0xCC: case 0xCE:
            case 0xF4: case 0xF5: case 0xF8: case 0xF9: case 0xFA:
            case 0xFB: case 0xFC: case 0xFD:
            case 0x98: case 0x99: case 0x9B: case 0x9C: case 0x9D:
            case 0x9E: case 0x9F:
            case 0x6C: case 0x6D: case 0x6E: case 0x6F:
            case 0xE0: case 0xE1: case 0xE2: case 0xE3:
            case 0xE8: case 0xE9: case 0xEB:
            case 0xF1: case 0xC8: case 0xCA: case 0xCB:
            case 0xA4: case 0xA5: case 0xA6: case 0xA7:
            case 0xAA: case 0xAB: case 0xAC: case 0xAD:
            case 0xAE: case 0xAF:
            case 0xD4: case 0xD5: case 0xD6: case 0xD7:
            case 0x60: case 0x61: case 0x62:
                return false;
            default:
                return true;
        }
    }

    static Decoded decode(const std::uint8_t* code, std::size_t size) noexcept {
        Decoded result{};
        std::size_t cursor = 0;

        if (size == 0)
            return result;

        while (cursor < size && cursor < 15 && is_prefix(code[cursor]))
            ++cursor;
        if (cursor >= size || cursor >= 15)
            return result;

        if ((code[cursor] & 0xF0) == 0x40)
            ++cursor;
        if (cursor >= size)
            return result;

        const std::uint8_t opcode = code[cursor++];

        if (opcode == 0x0F) {
            if (cursor >= size)
                return result;
            const std::uint8_t second = code[cursor++];
            // 0F 38 与 0F 3A 是三字节 opcode，多带一个字节
            if (second == 0x38 || second == 0x3A) {
                if (cursor >= size)
                    return result;
                ++cursor;
            }
            return decode_modrm(code, size, cursor, result);
        }

        if (!has_modrm(opcode))
            return decode_without_modrm(code, size, cursor, opcode, result);

        return decode_modrm(code, size, cursor, result);
    }

    static Decoded decode_modrm(const std::uint8_t* code, std::size_t size,
                                std::size_t cursor, Decoded result) noexcept {
        if (cursor >= size)
            return Decoded{};

        const std::uint8_t modrm = code[cursor++];
        const std::size_t mod = modrm >> 6;
        const std::size_t rm = modrm & 0x7;

        bool rip_relative = false;

        if (mod == 0 && rm == 5) {
            // RIP 相对寻址，固定 32 位位移
            if (cursor + 4 > size)
                return Decoded{};
            rip_relative = true;
        } else if (rm == 4) {
            if (cursor >= size)
                return Decoded{};
            const std::uint8_t sib = code[cursor++];
            const std::size_t sib_base = sib & 0x7;
            if (mod == 0 && sib_base == 5) {
                if (cursor + 4 > size)
                    return Decoded{};
                rip_relative = true;
            } else if (mod == 1) {
                if (cursor + 1 > size)
                    return Decoded{};
                ++cursor;
            } else if (mod == 2) {
                if (cursor + 4 > size)
                    return Decoded{};
                cursor += 4;
            }
        } else if (mod == 1) {
            if (cursor + 1 > size)
                return Decoded{};
            ++cursor;
        } else if (mod == 2) {
            if (cursor + 4 > size)
                return Decoded{};
            cursor += 4;
        }

        result.disp_offset = cursor;
        result.has_rip_reference = rip_relative;

        if (rip_relative) {
            std::int32_t disp = 0;
            for (std::size_t i = 0; i < 4; ++i)
                disp |= static_cast<std::int32_t>(code[cursor + i]) << (i * 8);

            // RIP 指向下一条指令，位移相对该地址计算
            result.rip_target_offset =
                static_cast<std::int64_t>(cursor + 4) + disp;
            cursor += 4;
        }

        result.length = cursor;
        return result;
    }

    static Decoded decode_without_modrm(const std::uint8_t* code,
                                        std::size_t size, std::size_t cursor,
                                        std::uint8_t opcode,
                                        Decoded result) noexcept {
        (void)code;
        std::size_t trailing = 0;

        if (opcode >= 0xB8 && opcode <= 0xBF)
            trailing = 4;
        else if (opcode >= 0xB0 && opcode <= 0xB7)
            trailing = 1;
        else if (opcode >= 0x70 && opcode <= 0x7F)
            trailing = 1;
        else if (opcode == 0xE8 || opcode == 0xE9)
            trailing = 4;
        else if (opcode == 0xEB || opcode == 0xE0 || opcode == 0xE1 ||
                 opcode == 0xE2 || opcode == 0xE3)
            trailing = 1;
        else if (opcode == 0xC2 || opcode == 0xCA)
            trailing = 2;
        else if (opcode == 0x6A)
            trailing = 1;
        else if (opcode == 0x68 || opcode == 0x6B)
            trailing = 4;
        else if (opcode >= 0x04 && opcode <= 0x3D && (opcode & 0x07) == 0x04)
            trailing = 1;
        else if (opcode >= 0x04 && opcode <= 0x3D && (opcode & 0x07) == 0x05)
            trailing = 4;

        if (cursor + trailing > size)
            return Decoded{};

        result.length = cursor + trailing;
        return result;
    }
};

}  // namespace veil::platform
