#pragma once

#include "../config.hpp"
#include "../crypto/hkdf.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::evidence {

// 以证据为 info 派生会话密钥。
//
// 这是库内唯一的密钥派生入口。SecCore 曾并存两条派生路径，误用其一
// 即绕过整套证据链；veil 不提供不含证据的派生函数。
class Binder {
public:
    static constexpr std::size_t KEY_SIZE = 32;

    static bool derive(const void* key_material, std::size_t key_len,
                       const void* nonce, std::size_t nonce_len,
                       const void* evidence, std::size_t evidence_len,
                       std::uint8_t domain,
                       std::uint8_t out[KEY_SIZE]) noexcept {
        if (key_material == nullptr || key_len == 0)
            return false;
        if (nonce == nullptr || nonce_len == 0)
            return false;
        if (evidence == nullptr || evidence_len > MAX_EVIDENCE_BYTES)
            return false;
        if (out == nullptr)
            return false;

        // info = evidence ‖ domain。长度由证据长度决定，服务端按同一
        // 布局复现；域字节必须落在 hkdf 的截断阈值之内，否则会被丢弃。
        std::uint8_t info[MAX_EVIDENCE_BYTES + 1];
        const auto* bytes = static_cast<const std::uint8_t*>(evidence);
        for (std::size_t i = 0; i < evidence_len; ++i)
            info[i] = bytes[i];
        info[evidence_len] = domain;

        static_assert(MAX_EVIDENCE_BYTES + 1 <= HKDF_MAX_INFO,
                      "domain byte must survive the hkdf info bound");

        hkdf_sha256(key_material, key_len, nonce, nonce_len,
                    info, evidence_len + 1, out, KEY_SIZE);

        detail::secure_wipe(info, sizeof(info));
        return true;
    }
};

}  // namespace veil::evidence
