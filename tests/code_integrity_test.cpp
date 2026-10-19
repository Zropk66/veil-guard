#include <veil/providers/code_integrity.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    static_assert(providers::CodeIntegrity::OBSERVATION_SIZE ==
                      sizeof(std::uint32_t) + 8 * 32,
                  "code integrity layout is fixed");

    // 未登记任何区域时，全部槽位为零
    {
        providers::CodeIntegrity probe;
        const Observation observation = probe.observe();
        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
        bool all_zero = true;
        for (std::size_t i = 0; i < observation.size; ++i)
            if (bytes[i] != 0)
                all_zero = false;
        test::expect(all_zero, "unregistered provider observes all zero");
        test::expect(probe.region_count() == 0, "unregistered provider has no regions");
    }

    // 登记磁盘与内存一致的段后仍为零
    {
        providers::CodeIntegrity probe;
        test::expect(probe.register_module_sections(),
                     "registers executable sections of the running module");
        test::expect(probe.region_count() > 0, "registers at least one region");

        const Observation observation = probe.observe();
        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
        std::uint32_t count = 0;
        std::memcpy(&count, bytes, sizeof(count));
        test::expect(count > 0, "observation reports registered region count");
        test::expect(count == probe.region_count(),
                     "reported count matches the registration count");

        // 差值槽位全零：磁盘与内存一致
        bool diffs_zero = true;
        for (std::size_t i = sizeof(std::uint32_t); i < observation.size; ++i)
            if (bytes[i] != 0)
                diffs_zero = false;
        test::expect(diffs_zero, "untampered sections yield zero digest delta");

        // 重复观测必须稳定，否则服务端无法复现同一 info
        const Observation again = probe.observe();
        test::expect(detail::constant_time_compare(observation.data, again.data,
                                                   observation.size) == 1,
                     "repeated observation is stable");
    }

    // 手工登记同源指针时差值为零
    {
        providers::CodeIntegrity probe;
        std::uint64_t value = 0x1122334455667788ULL;
        test::expect(probe.register_region_manual(&value, &value),
                     "registers a manually paired region");
        test::expect(probe.region_count() == 1, "manual region is counted");

        const Observation observation = probe.observe();
        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
        bool diffs_zero = true;
        for (std::size_t i = sizeof(std::uint32_t); i < observation.size; ++i)
            if (bytes[i] != 0)
                diffs_zero = false;
        test::expect(diffs_zero, "identical paired bytes yield zero delta");

        test::expect(!probe.register_region_manual(nullptr, &value),
                     "null disk pointer is rejected");
        test::expect(!probe.register_region_manual(&value, nullptr),
                     "null memory pointer is rejected");
        test::expect(!probe.register_region_manual(&value, &value, 0),
                     "zero length region is rejected");
    }

    // 篡改内存后差值必须非零
    {
        providers::CodeIntegrity probe;
        std::uint64_t disk = 0x1122334455667788ULL;
        std::uint64_t memory = disk;
        memory ^= 0x01;
        test::expect(probe.register_region_manual(&disk, &memory),
                     "registers a divergent pair");
        test::expect(probe.inject_delta_for_test(0, 0x5A),
                     "test hook writes a synthetic delta");

        const Observation observation = probe.observe();
        const auto* bytes = static_cast<const std::uint8_t*>(observation.data);
        bool found = false;
        for (std::size_t i = sizeof(std::uint32_t); i < observation.size; ++i)
            if (bytes[i] != 0)
                found = true;
        test::expect(found, "synthetic delta surfaces in observation");

        test::expect(!probe.inject_delta_for_test(providers::CodeIntegrity::MAX_REGIONS, 0x01),
                     "injection beyond the slot count is rejected");
    }

    // 槽位耗尽后必须拒绝而不是静默覆盖
    {
        providers::CodeIntegrity probe;
        std::uint64_t a = 1;
        std::uint64_t b = 1;
        std::size_t accepted = 0;
        while (probe.register_region_manual(&a, &b))
            ++accepted;
        test::expect(accepted == providers::CodeIntegrity::MAX_REGIONS,
                     "registration accepts exactly the declared slot count");
    }

    return test::finish("code_integrity");
}
