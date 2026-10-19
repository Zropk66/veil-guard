#include <veil/detail/common.hpp>
#include <veil/platform/scan.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;
    using namespace veil::platform;

    // 归属判定
    {
        ModuleInfo first{};
        test::expect(module_at(0, &first), "reads a module for the ownership probe");
        test::expect(module_base_of(first.base) == first.base,
                     "ownership probe resolves a module base from its own start");
        test::expect(module_base_of(nullptr) == nullptr,
                     "null address owns no module");
        test::expect(module_base_of(&first) == nullptr,
                     "stack address owns no module");

        const auto* mid = static_cast<const std::uint8_t*>(first.base) +
                          first.size / 2;
        test::expect(module_base_of(mid) == first.base,
                     "mid module address resolves to the module base");

        const auto* past = static_cast<const std::uint8_t*>(first.base) +
                           first.size + 0x10000;
        test::expect(module_base_of(past) == nullptr,
                     "address past the module image owns no module");
    }

    // 干净进程中不存在外源可执行页
    {
        std::uint8_t hash[16];
        const std::uint32_t foreign = scan_foreign_executable_pages(hash);
        test::expect(foreign == 0,
                     "clean process has no foreign executable pages");

        bool hash_zero = true;
        for (std::size_t i = 0; i < sizeof(hash); ++i)
            if (hash[i] != 0)
                hash_zero = false;
        test::expect(hash_zero, "zero foreign count yields a zero address hash");

        // 重复扫描必须稳定
        invalidate_code_page_cache();
        std::uint8_t again[16];
        test::expect(scan_foreign_executable_pages(again) == foreign,
                     "foreign page scan is repeatable");
        test::expect(veil::detail::constant_time_compare(hash, again, 16) == 1,
                     "address hash is stable across scans");
    }

    // 自己映射一块可执行页后必须被检出
    {
        void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
        test::expect(page != nullptr, "allocates a private executable page");
        if (page != nullptr) {
            invalidate_code_page_cache();
            std::uint8_t hash[16];
            const std::uint32_t foreign = scan_foreign_executable_pages(hash);
            test::expect(foreign >= 1, "private executable page is detected");

            bool hash_nonzero = false;
            for (std::size_t i = 0; i < sizeof(hash); ++i)
                if (hash[i] != 0)
                    hash_nonzero = true;
            test::expect(hash_nonzero, "detected page contributes to the hash");

            // 改成不可执行后必须不再计入
            DWORD previous = 0;
            VirtualProtect(page, 0x1000, PAGE_READWRITE, &previous);
            invalidate_code_page_cache();
            std::uint8_t after[16];
            test::expect(scan_foreign_executable_pages(after) == 0,
                         "dropping execute permission removes the page");
            test::expect(veil::detail::constant_time_compare(after, after, 16) == 1,
                         "hash reset is well formed");

            VirtualFree(page, 0, MEM_RELEASE);
        }
    }

    // 页保护标志判定
    {
        RegionInfo info{};
        info.protect = PAGE_EXECUTE_READWRITE;
        test::expect(is_executable(info), "rwx page reports executable");
        test::expect(is_writable(info), "rwx page reports writable");
        test::expect(!is_guarded(info), "rwx page is not guarded");

        info.protect = PAGE_EXECUTE_READ | PAGE_GUARD;
        test::expect(is_executable(info), "guard does not clear execute");
        test::expect(is_guarded(info), "guard flag is detected");

        info.protect = PAGE_READONLY;
        test::expect(!is_executable(info), "read only page is not executable");
        test::expect(!is_writable(info), "read only page is not writable");

        info.protect = PAGE_NOACCESS;
        test::expect(!is_writable(info), "no access page is not writable");
    }

    // 守卫页扫描必须给出确定结果
    {
        std::uint64_t hash = 0;
        const std::uint32_t guarded = scan_guard_pages(&hash);
        invalidate_code_page_cache();
        std::uint64_t again = 0;
        test::expect(scan_guard_pages(&again) == guarded,
                     "guard page scan is repeatable");
        test::expect(hash == again, "guard page hash is stable");
    }

    // 全地址空间遍历必须终止并覆盖到本模块
    {
        RegionWalker walker;
        RegionInfo info{};
        bool found_self = false;
        std::size_t visited = 0;
        while (walker.next(&info) && visited < 100000) {
            ++visited;
            if (module_base_of(info.base) == GetModuleHandleA(nullptr))
                found_self = true;
        }
        test::expect(visited > 0, "walker visits at least one region");
        test::expect(found_self, "walker reaches the running module");
    }

    return test::finish("scan");
}
