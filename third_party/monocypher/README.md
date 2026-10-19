# Monocypher 4.0.3 (vendored)

来源：https://github.com/LoupVaillant/Monocypher
标签：4.0.3（commit 0d85f98c9d9b0227e42cf795cb527dff372b40a4）
许可证：BSD-2-Clause OR CC0-1.0（见 LICENCE.md）

## 保留文件

| 文件 | SHA256 |
|---|---|
| `src/monocypher.c` | `91594377D2044C7212E88AEEAB7FB5A03078F4FACE45E50A5B0635B52D8F89B7` |
| `src/monocypher.h` | `7911A870E0B26D301EC552015B89ABC70091AE81E8830385791E936A8F828C65` |
| `src/optional/monocypher-ed25519.c` | `BDECE3B1C55790527FE054FD7230AEE0DCFA76CB564FFA6F3129EEC0DAC9AF2A` |
| `src/optional/monocypher-ed25519.h` | `40D90A7E146929E961EF6900F8C471B6FE1A8C4CE41D0BF063D371E5FFD5BAF2` |

## 为何需要两个文件

`src/monocypher.c` 提供 Curve25519 点运算；RFC 8032 签名与 SHA-512 位于
`src/optional/monocypher-ed25519.c`。前者是后者的依赖，两者都必须编译。

## 为何选 Ed25519 而非 Monocypher 自有的 EdDSA

Monocypher 顶层的 `crypto_eddsa_*` 使用 BLAKE2b 作为哈希，与 `lib/crypto-sign.ts`
中 Node `crypto.sign(null, ...)` 产生的 RFC 8032（SHA-512）签名不兼容。
客户端验签必须走 `crypto_ed25519_check`。

## 升级流程

1. 拉取目标 tag，重新计算上述四个文件的 SHA256
2. 对照 `CHANGELOG.md` 确认无破坏性 API 变更
3. 更新本文件的标签、commit 与哈希
4. 运行 `tests/ed25519_test.cpp` 确认与服务端签名互通
