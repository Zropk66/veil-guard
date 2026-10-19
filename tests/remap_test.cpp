#include <veil/detail/common.hpp>
#include <veil/platform/remap.hpp>
#include "support/test_main.hpp"

#include <cstring>

namespace {

volatile int g_stamp = 7;

VEIL_NOINLINE int add_stamp(int value) {
    return value + g_stamp;
}

VEIL_NOINLINE int nested(int depth) {
    volatile int local = depth;
    if (depth <= 0)
        return local;
    return nested(depth - 1) + 1;
}

VEIL_NOINLINE int sum_to(int limit) {
    int total = 0;
    for (int i = 0; i <= limit; ++i)
        total += i;
    return total;
}

}  // namespace

int main() {
    using namespace veil;
    using namespace veil::platform;

    const void* module = static_cast<const void*>(GetModuleHandleA(nullptr));

    test::expect(add_stamp(1) == 1 + g_stamp, "original function computes");

    // 函数边界查询
    {
        const void* begin = nullptr;
        std::size_t size = 0;
        const void* target = reinterpret_cast<const void*>(&add_stamp);
        test::expect(RemappedCode::function_bounds(module, target, &begin, &size),
                     "resolves the function bounds");
        test::expect(begin != nullptr, "bounds report a begin address");
        test::expect(size > 0, "bounds report a nonzero size");

        const auto begin_address = reinterpret_cast<std::uintptr_t>(begin);
        const auto target_address = reinterpret_cast<std::uintptr_t>(target);
        test::expect(target_address >= begin_address &&
                         target_address < begin_address + size,
                     "the target lies inside the reported bounds");

        test::expect(!RemappedCode::function_bounds(module, module, &begin, &size),
                     "image base is not inside a function");

        std::uint8_t outside[32]{};
        test::expect(!RemappedCode::function_bounds(module, outside, &begin, &size),
                     "address outside the image has no bounds");
    }

    // 重映射并调用
    {
        RemappedCode code;
        const void* target = reinterpret_cast<const void*>(&add_stamp);
        test::expect(code.map_function(module, target),
                     "maps the function into a private page");
        if (code.ready()) {
            test::expect(code.entry() != nullptr, "mapped page exposes an entry");
            test::expect(code.entry() != target, "mapped page differs from the origin");
            test::expect(code.delta() != 0, "mapped page reports a nonzero delta");

            using Fn = int (*)(int);
            const auto moved = reinterpret_cast<Fn>(code.entry());
            const auto original = reinterpret_cast<Fn>(
                const_cast<void*>(target));

            test::expect(moved(41) == original(41),
                         "remapped function matches the original result");
            test::expect(moved(0) == original(0),
                         "remapped function matches on a zero argument");
            test::expect(moved(-5) == original(-5),
                         "remapped function matches on a negative argument");

            // 外部数据被改动后两侧必须同步反映，说明 RIP 相对寻址
            // 指向的仍是同一份数据，而不是被复制了一份
            const int saved = g_stamp;
            g_stamp = 1000;
            test::expect(moved(2) == 2 + g_stamp,
                         "remapped function reads the live global");
            test::expect(original(2) == moved(2),
                         "both copies observe the same global");
            g_stamp = saved;

            // 篡改原页不得影响新页上的执行
            auto* mutable_target = const_cast<std::uint8_t*>(
                static_cast<const std::uint8_t*>(target));
            DWORD previous = 0;
            if (VirtualProtect(mutable_target, 16, PAGE_EXECUTE_READWRITE,
                               &previous) != 0) {
                const std::uint8_t saved_byte = *mutable_target;
                *mutable_target = 0xCC;
                test::expect(moved(7) == 7 + g_stamp,
                             "patching the origin does not affect the mapped copy");
                *mutable_target = saved_byte;
                VirtualProtect(mutable_target, 16, previous, &previous);
            }

            code.release();
            test::expect(!code.ready(), "release clears the ready state");
            test::expect(code.entry() == nullptr, "release drops the mapped page");
        }
    }

    // 含展开信息的递归函数
    {
        RemappedCode code;
        const void* target = reinterpret_cast<const void*>(&nested);
        test::expect(code.map_function(module, target),
                     "maps a recursive function");
        if (code.ready()) {
            using Fn = int (*)(int);
            const auto moved = reinterpret_cast<Fn>(code.entry());
            test::expect(moved(4) == 4, "remapped recursion terminates correctly");
            test::expect(moved(0) == 0, "remapped recursion handles the base case");
            code.release();
        }
    }

    // 含循环与跳转的函数
    {
        RemappedCode code;
        const void* target = reinterpret_cast<const void*>(&sum_to);
        test::expect(code.map_function(module, target),
                     "maps a function with a loop");
        if (code.ready()) {
            using Fn = int (*)(int);
            const auto moved = reinterpret_cast<Fn>(code.entry());
            test::expect(moved(10) == 55, "remapped loop computes correctly");
            test::expect(moved(0) == 0, "remapped loop handles zero iterations");
            code.release();
        }
    }

    // 输入校验
    {
        RemappedCode code;
        const void* target = reinterpret_cast<const void*>(&add_stamp);
        test::expect(!code.map_function(nullptr, target),
                     "null module is rejected");
        test::expect(!code.map_function(module, nullptr),
                     "null address is rejected");
        test::expect(!code.map(module, nullptr, 0x10), "null region is rejected");
        test::expect(!code.map(module, target, 0), "zero size is rejected");

        std::uint8_t outside[64]{};
        test::expect(!code.map(module, outside, sizeof(outside)),
                     "address outside the image is rejected");
        test::expect(!code.map(module, module, 0x7FFFFFFF),
                     "region exceeding the image is rejected");
        test::expect(!code.ready(), "failed mapping leaves the object unready");
    }

    // 重复映射必须释放上一份
    {
        RemappedCode code;
        const void* target = reinterpret_cast<const void*>(&add_stamp);
        for (int round = 0; round < 4; ++round) {
            test::expect(code.map_function(module, target),
                         "repeated mapping succeeds");
            test::expect(code.ready(), "repeated mapping reports ready");
        }
        using Fn = int (*)(int);
        const auto moved = reinterpret_cast<Fn>(code.entry());
        test::expect(moved(3) == 3 + g_stamp,
                     "the last mapping is still callable");
    }

    return test::finish("remap");
}
