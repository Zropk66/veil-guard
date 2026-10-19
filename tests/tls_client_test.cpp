#include <veil/detail/common.hpp>
#include <veil/transport/cert_pin.hpp>
#include <veil/transport/tls_client.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;
    using namespace veil::transport;

    // 未配置的 pin 必须可区分于「配置成全零」
    {
        const CertPin empty;
        test::expect(!empty.configured(), "default pin reports unconfigured");

        std::uint8_t zeros[CertPin::DIGEST_SIZE]{};
        const CertPin zeroed(zeros);
        test::expect(zeroed.configured(),
                     "explicit zero digest still counts as configured");

        const CertPin null_pin(static_cast<const std::uint8_t*>(nullptr));
        test::expect(!null_pin.configured(), "null digest leaves pin unconfigured");
    }

    // 配置后必须逐字节反映输入
    {
        std::uint8_t digest[CertPin::DIGEST_SIZE];
        for (std::size_t i = 0; i < sizeof(digest); ++i)
            digest[i] = static_cast<std::uint8_t>(i * 5 + 7);

        const CertPin pin(digest);
        test::expect(pin.configured(), "configured pin reports configured");
        test::expect(veil::detail::constant_time_compare(pin.digest(), digest,
                                                   CertPin::DIGEST_SIZE) == 1,
                     "pin stores the supplied digest");
    }

    // 握手前置条件：未连接时不得报告已连接，也不得留下指纹
    {
        TlsClient client;
        test::expect(!client.connected(), "fresh client is not connected");

        bool digest_zero = true;
        for (std::size_t i = 0; i < CertPin::DIGEST_SIZE; ++i)
            if (client.peer_digest()[i] != 0)
                digest_zero = false;
        test::expect(digest_zero, "unconnected client exposes a zero digest");

        // 空主机名必须拒绝
        test::expect(!client.connect_to(nullptr, 443, CertPin{}),
                     "null host is rejected");
    }

    // 连接不存在的端口必须失败而不是挂起或误报成功
    {
        TlsClient client;
        test::expect(!client.connect_to("127.0.0.1", 1, CertPin{}),
                     "connect to a closed port fails");
        test::expect(!client.connected(),
                     "failed connect leaves the client disconnected");
    }

    // probe_pin 的输入校验
    {
        std::uint8_t digest[CertPin::DIGEST_SIZE];
        test::expect(!probe_pin(nullptr, 443, digest),
                     "probe rejects a null host");
        test::expect(!probe_pin("127.0.0.1", 1, nullptr),
                     "probe rejects a null output");
        test::expect(!probe_pin("127.0.0.1", 1, digest),
                     "probe fails against a closed port");
    }

    // 应用数据收发的前置条件：未握手时必须拒绝而不是静默返回
    {
        TlsClient client;
        std::uint8_t buffer[64];

        test::expect(!client.send(buffer, sizeof(buffer)),
                     "send before handshake is rejected");
        test::expect(!client.recv(buffer, sizeof(buffer)),
                     "recv before handshake is rejected");
        test::expect(!client.send(nullptr, 16),
                     "send with a null buffer is rejected");
        test::expect(!client.recv(nullptr, 16),
                     "recv with a null buffer is rejected");
        test::expect(!client.send(buffer, 0), "zero length send is rejected");
        test::expect(!client.recv(buffer, 0), "zero length recv is rejected");
        test::expect(client.pending_bytes() == 0,
                     "fresh client has no pending plaintext");
    }

    // 握手失败后收发同样不可用
    {
        TlsClient client;
        client.connect_to("127.0.0.1", 1, CertPin{});
        std::uint8_t buffer[16];
        test::expect(!client.send(buffer, sizeof(buffer)),
                     "send after a failed handshake is rejected");
        test::expect(!client.recv(buffer, sizeof(buffer)),
                     "recv after a failed handshake is rejected");
        test::expect(client.pending_bytes() == 0,
                     "failed handshake leaves no pending plaintext");
    }

    return test::finish("tls_client");
}
