#include <veil/detail/common.hpp>
#include <veil/evidence/layout.hpp>
#include <veil/providers/anti_debug.hpp>
#include <veil/providers/cert_pin.hpp>
#include <veil/providers/module_topo.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;

    using Small = evidence::Layout<providers::AntiDebugSnapshot,
                                   providers::ModuleTopology>;

    test::expect(Small::SIZE == 16 + 20,
                 "layout size is the sum of provider sizes");

    std::uint8_t buffer[Small::SIZE];
    std::memset(buffer, 0xCC, sizeof(buffer));

    const providers::AntiDebugSnapshot debug_probe;
    const providers::ModuleTopology topo_probe;
    test::expect(Small::serialize(buffer, sizeof(buffer), debug_probe, topo_probe),
                 "serialize succeeds with exact capacity");

    // 顺序必须与模板参数一致
    const Observation debug = debug_probe.observe();
    test::expect(detail::constant_time_compare(buffer, debug.data, debug.size) == 1,
                 "first provider occupies the leading bytes");

    const Observation topo = topo_probe.observe();
    test::expect(detail::constant_time_compare(buffer + 16, topo.data, topo.size) == 1,
                 "second provider follows the first");

    std::uint8_t small_buffer[Small::SIZE - 1];
    test::expect(!Small::serialize(small_buffer, sizeof(small_buffer),
                                   debug_probe, topo_probe),
                 "serialize rejects insufficient capacity");

    test::expect(!Small::serialize(nullptr, Small::SIZE, debug_probe, topo_probe),
                 "serialize rejects null buffer");

    // 单 provider 布局
    using Single = evidence::Layout<providers::AntiDebugSnapshot>;
    test::expect(Single::SIZE == 16, "single provider layout size is exact");
    std::uint8_t single[Single::SIZE];
    test::expect(Single::serialize(single, sizeof(single), debug_probe),
                 "single provider layout serializes");

    // 全量布局必须落在证据上限之内
    using Full = evidence::Layout<providers::AntiDebugSnapshot,
                                  providers::ModuleTopology,
                                  providers::CertificatePin>;
    test::expect(Full::SIZE == 16 + 20 + 32, "full layout size is the sum");
    static_assert(Full::SIZE <= MAX_EVIDENCE_BYTES,
                  "full layout must fit the evidence bound");

    // 证书指纹槽位在未设置时必须为零
    providers::CertificatePin empty_pin;
    const Observation pin = empty_pin.observe();
    bool pin_zero = true;
    for (std::size_t i = 0; i < pin.size; ++i)
        if (static_cast<const std::uint8_t*>(pin.data)[i] != 0)
            pin_zero = false;
    test::expect(pin_zero, "unset certificate pin observes all zero");

    // 设置后必须逐字节反映输入
    std::uint8_t digest[32];
    for (std::size_t i = 0; i < sizeof(digest); ++i)
        digest[i] = static_cast<std::uint8_t>(i * 5 + 1);
    providers::CertificatePin pinned(digest);
    const Observation observed = pinned.observe();
    test::expect(detail::constant_time_compare(observed.data, digest, 32) == 1,
                 "certificate pin observes the supplied digest");

    return test::finish("layout");
}
