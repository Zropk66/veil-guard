#include <veil/detail/common.hpp>
#include <veil/platform/hwid.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    char id[platform::MachineId::BUFFER_SIZE];
    std::memset(id, 'X', sizeof(id));

    test::expect(platform::MachineId::capture(id, sizeof(id)),
                 "captures a machine identifier");

    // 固定长度：来源可用性不得改变长度，否则服务端比较会失去意义
    test::expect(std::strlen(id) == platform::MachineId::HEX_SIZE,
                 "identifier has the declared length");

    // 全部字符必须是小写十六进制
    bool hex_only = true;
    for (std::size_t i = 0; i < platform::MachineId::HEX_SIZE; ++i) {
        const char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            hex_only = false;
    }
    test::expect(hex_only, "identifier is lowercase hexadecimal");

    // 落在服务端的机器标识上限之内
    test::expect(std::strlen(id) <= 127,
                 "identifier fits the protocol bound");

    // 同一台机器重复采集必须一致，否则每次验证都会重新绑定
    char again[platform::MachineId::BUFFER_SIZE];
    test::expect(platform::MachineId::capture(again, sizeof(again)),
                 "repeats the capture");
    test::expect(std::strcmp(id, again) == 0,
                 "identifier is stable across captures");

    // 不得退回全零或固定串，否则所有机器标识相同
    bool all_zero = true;
    for (std::size_t i = 0; i < platform::MachineId::HEX_SIZE; ++i)
        if (id[i] != '0')
            all_zero = false;
    test::expect(!all_zero, "identifier is not a zero string");

    // 输入校验
    {
        char small[8];
        test::expect(!platform::MachineId::capture(small, sizeof(small)),
                     "undersized buffer is rejected");
        test::expect(!platform::MachineId::capture(nullptr, 64),
                     "null buffer is rejected");

        char exact[platform::MachineId::HEX_SIZE];
        test::expect(!platform::MachineId::capture(exact, sizeof(exact)),
                     "buffer without room for the terminator is rejected");
    }

    return test::finish("hwid");
}
