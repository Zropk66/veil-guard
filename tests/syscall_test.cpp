#include <veil/platform/memory.hpp>
#include <veil/platform/syscall.hpp>
#include "support/test_main.hpp"

#include <windows.h>

int main() {
    using namespace veil;
    using namespace veil::platform;

    const std::uint32_t ssn = syscall_number("NtQueryVirtualMemory");
    test::expect(ssn != 0, "resolves NtQueryVirtualMemory syscall number");
    test::expect(ssn < 0x1000, "syscall number stays in valid range");

    const std::uint32_t again = syscall_number("NtQueryVirtualMemory");
    test::expect(ssn == again, "syscall number resolution is stable");

    const std::uint32_t other = syscall_number("NtClose");
    test::expect(other != 0 && other != ssn,
                 "distinct exports resolve to distinct numbers");

    // Nt* 与同名 Zw* 共享同一 stub，必须推出同一个号
    test::expect(syscall_number("ZwQueryVirtualMemory") == ssn,
                 "Zw alias resolves to the same number as its Nt counterpart");

    test::expect(syscall_number("ThisExportDoesNotExist") == 0,
                 "unknown export resolves to zero");
    test::expect(syscall_number(nullptr) == 0, "null export name resolves to zero");
    test::expect(syscall_number("") == 0, "empty export name resolves to zero");

    // 直发路径：查询当前进程中一个确定已提交的地址，验证调用真的到达内核
    const std::uint32_t query_ssn = syscall_number("NtQueryVirtualMemory");
    std::uint8_t buffer[64]{};
    const long status = syscall_direct(
        query_ssn,
        static_cast<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(
            GetCurrentProcess())),
        static_cast<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(
            reinterpret_cast<const void*>(&status))),
        0,
        reinterpret_cast<std::uintptr_t>(buffer),
        sizeof(buffer),
        0);
    test::expect(status == 0, "direct syscall reaches kernel and returns success");

    // 内存查询包装必须与实际分配状态一致
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    test::expect(page != nullptr, "allocates a probe page");
    if (page != nullptr) {
        RegionInfo info{};
        test::expect(query_region(page, &info), "queries allocated region");
        test::expect(info.state == MEM_COMMIT, "region reports committed");
        test::expect((info.protect & PAGE_READWRITE) != 0,
                     "region reports read write protection");
        test::expect(info.base != nullptr, "region reports a base address");
        test::expect(info.size >= 4096, "region reports a plausible size");
        test::expect(is_writable(info), "region reports as writable");

        const RegionInfo snapshot = info;
        std::uint8_t* slot = static_cast<std::uint8_t*>(page);
        slot[0] = 0x5A;
        RegionInfo reread{};
        test::expect(query_region(page, &reread) &&
                         reread.protect == snapshot.protect,
                     "region protection is stable across queries");

        test::expect(!query_region(nullptr, &info), "null address is rejected");
        test::expect(!query_region(page, nullptr), "null output is rejected");
        VirtualFree(page, 0, MEM_RELEASE);
    }

    return veil::test::finish("syscall");
}
