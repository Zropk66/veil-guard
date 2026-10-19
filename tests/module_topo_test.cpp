#include <veil/detail/common.hpp>
#include <veil/providers/module_topo.hpp>
#include "support/test_main.hpp"

#include <cstring>

namespace {

std::uint32_t len(const wchar_t* text) {
    std::uint32_t n = 0;
    while (text[n] != L'\0')
        ++n;
    return n;
}

}  // namespace

int main() {
    using namespace veil;

    static_assert(providers::ModuleTopology::OBSERVATION_SIZE == 20,
                  "module topology layout is fixed");

    providers::ModuleTopology probe;
    const Observation observation = probe.observe();
    test::expect(observation.size == 20, "observe returns declared size");
    test::expect(observation.data != nullptr, "observe returns a valid pointer");

    const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
    std::uint32_t foreign = 0;
    std::memcpy(&foreign, bytes, sizeof(foreign));

    // 测试进程自身从构建目录加载，会被判定为外源模块，这是预期行为。
    // 关键是 foreign 计数与路径哈希必须同时反映这一点。
    bool hash_nonzero = false;
    for (std::size_t i = sizeof(foreign); i < observation.size; ++i)
        if (bytes[i] != 0)
            hash_nonzero = true;

    test::expect((foreign == 0) == !hash_nonzero,
                 "foreign count and path hash agree");
    test::expect(foreign > 0, "test binary itself is classified as foreign");

    // 系统目录必须被判定为可信
    const wchar_t system32[] = L"c:\\windows\\system32\\ntdll.dll";
    test::expect(providers::ModuleTopology::is_path_trusted(system32, len(system32)),
                 "system32 path is trusted");
    const wchar_t upper[] = L"C:\\Windows\\System32\\KERNEL32.DLL";
    test::expect(providers::ModuleTopology::is_path_trusted(upper, len(upper)),
                 "trust check is case insensitive");
    const wchar_t winsxs[] =
        L"c:\\windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.22621.1_none_1a5b3c4d5e6f7081\\comctl32.dll";
    test::expect(providers::ModuleTopology::is_path_trusted(winsxs, len(winsxs)),
                 "winsxs path is trusted");

    // 前缀匹配不得放过伪装目录
    const wchar_t temp[] = L"c:\\temp\\evil.dll";
    test::expect(!providers::ModuleTopology::is_path_trusted(temp, len(temp)),
                 "temp path is untrusted");
    const wchar_t near_miss[] = L"c:\\windows\\system32evil\\x.dll";
    test::expect(!providers::ModuleTopology::is_path_trusted(near_miss, len(near_miss)),
                 "path with trusted prefix inside a longer name is untrusted");
    const wchar_t traversal[] = L"c:\\temp\\..\\windows\\system32\\x.dll";
    test::expect(!providers::ModuleTopology::is_path_trusted(traversal, len(traversal)),
                 "embedded traversal is not normalised into trust");

    // 边界输入
    test::expect(!providers::ModuleTopology::is_path_trusted(nullptr, 0),
                 "null path is untrusted");
    test::expect(!providers::ModuleTopology::is_path_trusted(L"", 0),
                 "empty path is untrusted");

    // 重复观测必须稳定
    const Observation again = probe.observe();
    test::expect(detail::constant_time_compare(observation.data, again.data,
                                               observation.size) == 1,
                 "repeated observation is stable");

    return test::finish("module_topo");
}
