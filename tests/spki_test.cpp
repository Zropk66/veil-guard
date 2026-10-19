#include <veil/detail/common.hpp>
#include <veil/transport/cert_pin.hpp>
#include "support/test_main.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::uint8_t> read_file(const char* path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}

}  // namespace

int main() {
    using namespace veil;

    // 期望值由 openssl 独立算出：
    //   openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256
    const char* expected_hex =
        "A2417E293C3070CF755546877063354199AAD30BEE6F0ED38BB054E2EA7D4CEC";

    const std::vector<std::uint8_t> der = read_file("tests/fixtures/spki_cert.der");
    test::expect(!der.empty(), "loads the fixture certificate");
    if (der.empty())
        return test::finish("spki");

    PCCERT_CONTEXT certificate = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(),
        static_cast<DWORD>(der.size()));
    test::expect(certificate != nullptr, "parses the fixture certificate");
    if (certificate == nullptr)
        return test::finish("spki");

    std::uint8_t digest[veil::transport::CertPin::DIGEST_SIZE];
    test::expect(transport::detail::spki_digest(certificate, digest),
                 "derives the subject public key info digest");

    std::uint8_t expected[32];
    for (std::size_t i = 0; i < sizeof(expected); ++i)
        expected[i] = static_cast<std::uint8_t>(
            (hex_nibble(expected_hex[i * 2]) << 4) |
            hex_nibble(expected_hex[i * 2 + 1]));

    test::expect(detail::constant_time_compare(digest, expected, 32) == 1,
                 "digest matches the independent openssl computation");

    // 同一证书重复求摘要必须稳定
    std::uint8_t again[32];
    transport::detail::spki_digest(certificate, again);
    test::expect(detail::constant_time_compare(digest, again, 32) == 1,
                 "digest is deterministic");

    // 摘要必须落在整个证书的公钥上，而不是证书本身的哈希
    {
        std::uint8_t whole[32];
        Sha256::hash(der.data(), der.size(), whole);
        test::expect(detail::constant_time_compare(digest, whole, 32) == 0,
                     "digest is not the certificate hash");
    }

    // 空输入必须拒绝
    test::expect(!transport::detail::spki_digest(nullptr, digest),
                 "null certificate is rejected");
    test::expect(!transport::detail::spki_digest(certificate, nullptr),
                 "null output is rejected");

    CertFreeCertificateContext(certificate);
    return test::finish("spki");
}
