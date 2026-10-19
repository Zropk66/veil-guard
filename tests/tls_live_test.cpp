#include <veil/transport/tls_client.hpp>
#include "support/test_main.hpp"

#include <cstdio>

int main() {
    using namespace veil;
    using namespace veil::transport;

    std::uint8_t probe_digest[CertPin::DIGEST_SIZE];
    bool probed = false;

    // 探测公网主机的指纹。无网络时跳过，不作为失败计。
    for (int attempt = 0; attempt < 2 && !probed; ++attempt)
        probed = probe_pin("example.com", 443, probe_digest);

    if (!probed) {
        std::printf("SKIP: no network reachability for the live handshake\n");
        return test::finish("tls_live");
    }

    test::expect(probed, "probes a live host certificate");
    test::expect(probe_pin("example.com", 443, probe_digest),
                 "probe is repeatable");

    // 探测两次必须得到同一指纹：证书在这段时间内不变
    std::uint8_t second[CertPin::DIGEST_SIZE];
    probe_pin("example.com", 443, second);
    test::expect(veil::detail::constant_time_compare(probe_digest, second,
                                                     CertPin::DIGEST_SIZE) == 1,
                 "probed digest is stable across connections");

    // 用实测指纹握手必须成功
    {
        const CertPin pin(probe_digest);
        TlsClient client;
        test::expect(client.connect_to("example.com", 443, pin),
                     "handshake succeeds with the matching pin");
        test::expect(client.connected(), "client reports connected");
        test::expect(veil::detail::constant_time_compare(client.peer_digest(),
                                                         probe_digest,
                                                         CertPin::DIGEST_SIZE) == 1,
                     "handshake exposes the same peer digest");
        client.close();
        test::expect(!client.connected(), "close clears the connected state");
    }

    // 指纹不符必须导致握手失败且无降级路径
    {
        std::uint8_t wrong[CertPin::DIGEST_SIZE];
        for (std::size_t i = 0; i < sizeof(wrong); ++i)
            wrong[i] = static_cast<std::uint8_t>(probe_digest[i] ^ 0xFF);
        const CertPin mismatched(wrong);

        TlsClient client;
        test::expect(!client.connect_to("example.com", 443, mismatched),
                     "handshake fails on a mismatched pin");
        test::expect(!client.connected(),
                     "mismatched pin leaves the client disconnected");
    }

    // 不配置 pin 时只做链校验，握手必须成功
    {
        TlsClient client;
        test::expect(client.connect_to("example.com", 443, CertPin{}),
                     "handshake succeeds without a pin");
        client.close();
    }

    return test::finish("tls_live");
}
