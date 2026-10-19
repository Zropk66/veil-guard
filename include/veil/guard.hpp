#pragma once

#include "config.hpp"
#include "detail/common.hpp"
#include "evidence/binder.hpp"
#include "evidence/layout.hpp"
#include "providers/entropy.hpp"

#include <cstddef>
#include <cstdint>

namespace veil {

// 装配入口。
//
// 不在构造时做任何文件读取或加密初始化：DllMain 持有加载器锁，
// 在其中调用 CreateFile 或首次加载 bcrypt 会死锁。全部工作推迟到
// 首次派生调用。
//
// 熵源的构造只读时间戳、RDRAND 与一次堆分配，均不触及加载器锁，
// 因此可以留在构造期。它不做任何文件或加密 provider 初始化。
//
// 布局类型由 provider 实参推导，不显式传模板参数。这样调用点写错
// 顺序或漏传 provider 都会在编译期失败，而不是悄悄派生出另一条链。
class Guard {
public:
    Guard() noexcept = default;

    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;

    // 以布局采集的观测为 info 派生会话密钥。
    //
    // 观测不满足零值基线时，派生出的是错误密钥而非「被拒绝」。
    // 调用方拿到的密钥看似合法，故障在后续 AEAD 认证阶段才显现。
    template <typename... Providers>
    bool derive_session_key(const void* card_key, std::size_t card_key_len,
                            const void* nonce, std::size_t nonce_len,
                            std::uint8_t domain,
                            std::uint8_t out[evidence::Binder::KEY_SIZE],
                            const Providers&... providers) noexcept {
        using Layout = evidence::Layout<Providers...>;

        std::uint8_t buffer[Layout::SIZE];
        const bool serialized =
            Layout::serialize(buffer, sizeof(buffer), providers...);
        const bool ok = serialized &&
                        evidence::Binder::derive(card_key, card_key_len,
                                                 nonce, nonce_len,
                                                 buffer, sizeof(buffer),
                                                 domain, out);
        detail::secure_wipe(buffer, sizeof(buffer));
        return ok;
    }

    // 采集一次观测并返回原始字节，供诊断工具与跨实现夹具使用。
    // 业务路径不得以此结果做任何判定。
    template <typename... Providers>
    bool capture(std::uint8_t* out, std::size_t capacity,
                 const Providers&... providers) noexcept {
        return evidence::Layout<Providers...>::serialize(out, capacity, providers...);
    }

    // 生成一次请求用的 nonce。服务端以同一 nonce 复现派生，因此每次
    // 请求都必须新取，复用会让 GCM 的密钥流重用。
    //
    // 熵源不经过 CNG 或 rand 导出，被改写这些导出不影响 nonce 的
    // 不可预测性。
    bool next_nonce(char* out, std::size_t capacity) noexcept {
        return entropy_.nonce_hex(out, capacity);
    }

private:
    providers::Entropy entropy_;
};

}  // namespace veil
