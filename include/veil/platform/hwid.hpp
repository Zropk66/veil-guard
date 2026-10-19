#pragma once

#include "../config.hpp"
#include "../crypto/sha256.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::platform {

// 机器标识采集。
//
// 取三处相互独立、随硬件或系统安装变化的来源：系统安装时生成的
// MachineGuid、系统盘卷序列号、主板 SMBIOS 的 System UUID。三者
// 拼接后取 SHA-256，输出定长十六进制串。
//
// 不单独依赖任何一项。虚拟机克隆会让 MachineGuid 重复，格式化会
// 改掉卷序列号，部分主板不填 SMBIOS UUID。三项同时相同才得到相同
// 标识，这个门槛足以区分真实设备。
//
// 输出是 32 个小写十六进制字符，落在 MAX_MACHINE_ID 之内。固定长度
// 让服务端的字符串比较不受来源可用性影响：某一项缺失时以零填充参与
// 摘要，长度不变。
class MachineId {
public:
    static constexpr std::size_t HEX_SIZE = 32;
    static constexpr std::size_t BUFFER_SIZE = HEX_SIZE + 1;

    // 采集并写入以空字符结尾的十六进制串。capacity 需大于 HEX_SIZE。
    // 返回 false 表示三项来源全部不可用，此时不写入任何内容。
    static bool capture(char* out, std::size_t capacity) noexcept {
        if (out == nullptr || capacity <= HEX_SIZE)
            return false;

        std::uint8_t material[64]{};
        std::size_t used = 0;
        bool any_source = false;

        wchar_t guid[64]{};
        if (read_machine_guid(guid, 64)) {
            std::size_t i = 0;
            while (guid[i] != L'\0' && used < sizeof(material)) {
                material[used++] = static_cast<std::uint8_t>(guid[i]);
                ++i;
            }
            any_source = true;
        }

        std::uint32_t volume = 0;
        if (read_volume_serial(&volume)) {
            for (std::size_t i = 0; i < 4 && used < sizeof(material); ++i)
                material[used++] = static_cast<std::uint8_t>(volume >> (i * 8));
            any_source = true;
        }

        std::uint8_t uuid[16]{};
        if (read_smbios_uuid(uuid)) {
            for (std::size_t i = 0; i < 16 && used < sizeof(material); ++i)
                material[used++] = uuid[i];
            any_source = true;
        }

        if (!any_source) {
            veil::detail::secure_wipe(material, sizeof(material));
            return false;
        }

        std::uint8_t digest[Sha256::DIGEST_SIZE];
        Sha256::hash(material, used, digest);

        static constexpr char kHex[] = "0123456789abcdef";
        for (std::size_t i = 0; i < HEX_SIZE / 2; ++i) {
            out[i * 2] = kHex[digest[i] >> 4];
            out[i * 2 + 1] = kHex[digest[i] & 0x0F];
        }
        out[HEX_SIZE] = '\0';

        veil::detail::secure_wipe(material, sizeof(material));
        veil::detail::secure_wipe(digest, sizeof(digest));
        return true;
    }

private:
    static bool read_machine_guid(wchar_t* out, std::size_t capacity) noexcept {
        DWORD size = static_cast<DWORD>(capacity * sizeof(wchar_t));
        const LSTATUS status = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid",
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            nullptr, out, &size);
        if (status != ERROR_SUCCESS)
            return false;

        return out[0] != L'\0';
    }

    static bool read_volume_serial(std::uint32_t* out) noexcept {
        wchar_t windows_dir[MAX_PATH];
        const DWORD written = GetWindowsDirectoryW(windows_dir, MAX_PATH);
        if (written == 0 || written >= MAX_PATH)
            return false;

        // 根目录形如 "C:\"
        wchar_t root[4] = {windows_dir[0], L':', L'\\', L'\0'};

        DWORD serial = 0;
        if (!GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr,
                                   nullptr, 0))
            return false;

        *out = static_cast<std::uint32_t>(serial);
        return true;
    }

    // SMBIOS System Information 结构里的 UUID 字段。
    //
    // 固件表以 RawSMBIOSData 封装，表体是一串变长结构：四字节头部后
    // 跟格式区，再跟以双零结尾的字符串区。逐条跳过，按类型 1 定位。
    // 全零与全 FF 都表示厂商未填，按缺失处理。
    static bool read_smbios_uuid(std::uint8_t out[16]) noexcept {
        // 'RSMB' 的小端整数值。写成字符常量会触发多字符警告，
        // 且不同编译器对多字符常量的求值顺序不一致。
        constexpr DWORD kRawSmbiosProvider = 0x52534D42u;
        const DWORD needed = GetSystemFirmwareTable(kRawSmbiosProvider, 0,
                                                    nullptr, 0);
        if (needed == 0 || needed > 64u * 1024u)
            return false;

        std::uint8_t buffer[64 * 1024];
        if (GetSystemFirmwareTable(kRawSmbiosProvider, 0, buffer, needed) != needed)
            return false;

        // RawSMBIOSData 头部八字节，之后是表体
        if (needed < 8)
            return false;

        const std::size_t table_length =
            static_cast<std::size_t>(buffer[4]) |
            (static_cast<std::size_t>(buffer[5]) << 8) |
            (static_cast<std::size_t>(buffer[6]) << 16) |
            (static_cast<std::size_t>(buffer[7]) << 24);

        std::size_t cursor = 8;
        const std::size_t end =
            cursor + table_length < needed ? cursor + table_length : needed;

        while (cursor + 4 <= end) {
            const std::uint8_t type = buffer[cursor];
            const std::uint8_t length = buffer[cursor + 1];

            if (length < 4 || cursor + length > end)
                break;

            if (type == 1 && length >= 0x19) {
                const std::uint8_t* uuid = buffer + cursor + 0x08;

                bool all_zero = true;
                bool all_ff = true;
                for (std::size_t i = 0; i < 16; ++i) {
                    if (uuid[i] != 0) all_zero = false;
                    if (uuid[i] != 0xFF) all_ff = false;
                }
                if (all_zero || all_ff)
                    return false;

                for (std::size_t i = 0; i < 16; ++i)
                    out[i] = uuid[i];
                return true;
            }

            // 跳过格式区与字符串区。字符串区以双零结尾，格式区末尾
            // 恰好是零字节时字符串区只剩一个零，因此要单独判断。
            std::size_t next = cursor + length;
            if (next + 1 >= end)
                break;

            if (buffer[next] == 0 && buffer[next + 1] == 0) {
                cursor = next + 2;
                continue;
            }

            while (next + 1 < end &&
                   !(buffer[next] == 0 && buffer[next + 1] == 0))
                ++next;
            cursor = next + 2;
        }

        return false;
    }
};

}  // namespace veil::platform
