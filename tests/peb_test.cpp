#include <veil/platform/peb.hpp>
#include "support/test_main.hpp"

#include <cstring>
#include <cwchar>

namespace {

// 手数长度易错，统一由字面量自身求长
constexpr std::uint32_t len(const wchar_t* text) {
    std::uint32_t n = 0;
    while (text[n] != L'\0')
        ++n;
    return n;
}

}  // namespace

int main() {
    using namespace veil;
    using namespace veil::platform;

    const std::size_t count = module_count();
    test::expect(count > 0, "enumerates at least one module");
    test::expect(count < 4096, "module count stays plausible");

    ModuleInfo first{};
    test::expect(module_at(0, &first), "reads first module entry");
    test::expect(first.base != nullptr, "first module has a base address");
    test::expect(first.path_length > 0, "first module has a path");

    bool found_ntdll = false;
    bool found_kernel32 = false;
    bool paths_terminated = true;
    for (std::size_t i = 0; i < count; ++i) {
        ModuleInfo info{};
        if (!module_at(i, &info))
            continue;
        if (info.path == nullptr || info.path_length == 0)
            paths_terminated = false;
        if (contains_ci(info.path, info.path_length, L"ntdll.dll"))
            found_ntdll = true;
        if (contains_ci(info.path, info.path_length, L"kernel32.dll"))
            found_kernel32 = true;
    }
    test::expect(found_ntdll, "module list contains ntdll");
    test::expect(found_kernel32, "module list contains kernel32");
    test::expect(paths_terminated, "every enumerated entry carries a path");

    test::expect(!module_at(count, &first), "index past end returns false");
    test::expect(!module_at(0, nullptr), "null output returns false");

    const void* ntdll_base = module_base_ci(L"ntdll.dll");
    test::expect(ntdll_base != nullptr, "looks up ntdll base by name");
    test::expect(module_base_ci(L"NTDLL.DLL") == ntdll_base,
                 "module lookup is case insensitive");
    test::expect(module_base_ci(L"nosuchmodule_xyz.dll") == nullptr,
                 "unknown module resolves to null");

    // contains_ci 是纯子串搜索，不承担路径分量语义；
    // 防形近目录由 module_base_ci 的尾部比较负责
    const wchar_t embedded[] = L"c:\\fakentdll.dll\\x";
    test::expect(contains_ci(embedded, len(embedded), L"ntdll.dll"),
                 "substring search matches a name embedded mid path");
    const wchar_t genuine[] = L"c:\\windows\\system32\\ntdll.dll";
    test::expect(contains_ci(genuine, len(genuine), L"ntdll.dll"),
                 "substring search finds a genuine tail component");
    test::expect(!contains_ci(nullptr, 0, L"ntdll.dll"),
                 "null haystack is rejected");
    test::expect(!contains_ci(L"abc", 3, nullptr),
                 "null needle is rejected");
    test::expect(!contains_ci(L"abc", 3, L""),
                 "empty needle is rejected");

    const wchar_t mixed_case[] = L"C:\\Windows\\System32\\x.dll";
    test::expect(starts_with_ci(mixed_case, len(mixed_case),
                                L"c:\\windows\\system32"),
                 "prefix comparison is case insensitive");
    const wchar_t near_miss[] = L"c:\\windows\\system32evil\\x.dll";
    test::expect(!starts_with_ci(near_miss, len(near_miss),
                                 L"c:\\windows\\system32\\"),
                 "prefix comparison does not match a longer directory name");

    return veil::test::finish("peb");
}
