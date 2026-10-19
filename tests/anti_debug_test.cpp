#include <veil/providers/anti_debug.hpp>
#include <veil/providers/entropy.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    // 熵源：独立实例必须产出不同流，同实例连续调用必须推进
    {
        providers::Entropy a;
        providers::Entropy b;
        std::uint8_t stream_a[64];
        std::uint8_t stream_b[64];
        a.generate(stream_a, sizeof(stream_a));
        b.generate(stream_b, sizeof(stream_b));
        test::expect(detail::constant_time_compare(stream_a, stream_b, 64) == 0,
                     "independent entropy instances diverge");

        std::uint8_t first[32];
        std::uint8_t second[32];
        a.generate(first, sizeof(first));
        a.generate(second, sizeof(second));
        test::expect(detail::constant_time_compare(first, second, 32) == 0,
                     "successive generate calls advance the stream");

        bool nonzero = false;
        for (std::size_t i = 0; i < 64; ++i)
            if (stream_a[i] != 0)
                nonzero = true;
        test::expect(nonzero, "entropy output is not all zero");

        // 重新播种必须改变后续流，否则密钥材料在进程内被完全复用
        std::uint8_t before_reseed[32];
        std::uint8_t after_reseed[32];
        a.reseed();
        a.generate(before_reseed, sizeof(before_reseed));
        a.reseed();
        a.generate(after_reseed, sizeof(after_reseed));
        test::expect(detail::constant_time_compare(before_reseed, after_reseed, 32) == 0,
                     "reseed produces new key material");
    }

    // 反调试观测：结构大小固定，未调试环境下字段为零
    {
        static_assert(providers::AntiDebugSnapshot::OBSERVATION_SIZE == 16,
                      "anti-debug observation layout is fixed");

        const providers::AntiDebugSnapshot snapshot{};
        test::expect(snapshot.being_debugged == 0,
                     "default snapshot has no debug flag");
        test::expect(snapshot.hardware_breakpoints == 0,
                     "default snapshot has no hardware breakpoints");

        const Observation observation = providers::AntiDebugSnapshot::observe();
        test::expect(observation.size == 16, "observe returns the declared size");
        test::expect(observation.data != nullptr, "observe returns a valid pointer");

        // 未附加调试器时全部字节必须为零，这是零登记设计的前提
        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
        bool all_zero = true;
        for (std::size_t i = 0; i < observation.size; ++i)
            if (bytes[i] != 0)
                all_zero = false;
        test::expect(all_zero, "undebugged observation is all zero");

        // 连续观测必须一致：单次采集内不得引入抖动
        const Observation again = providers::AntiDebugSnapshot::observe();
        test::expect(detail::constant_time_compare(observation.data, again.data,
                                                   observation.size) == 1,
                     "repeated observation is stable");

        const providers::AntiDebugSnapshot captured =
            providers::AntiDebugSnapshot::capture();
        test::expect(captured.being_debugged == snapshot.being_debugged,
                     "capture agrees with the default state");
    }

    return test::finish("anti_debug");
}
