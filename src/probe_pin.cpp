#include "../include/veil/transport/tls_client.hpp"

namespace veil::transport {

// 探测指定主机的证书公钥指纹。该入口不校验任何指纹，只供离线
// 密钥轮换工具调用，业务路径不得引用。
bool probe_pin(const char* host, std::uint16_t port,
               std::uint8_t out[CertPin::DIGEST_SIZE]) noexcept {
    if (host == nullptr || out == nullptr)
        return false;

    for (std::size_t i = 0; i < CertPin::DIGEST_SIZE; ++i)
        out[i] = 0;

    const CertPin unconfigured;
    TlsClient client;
    if (!client.connect_to(host, port, unconfigured))
        return false;

    const std::uint8_t* observed = client.peer_digest();
    if (observed == nullptr)
        return false;

    for (std::size_t i = 0; i < CertPin::DIGEST_SIZE; ++i)
        out[i] = observed[i];

    client.close();
    return true;
}

}  // namespace veil::transport
