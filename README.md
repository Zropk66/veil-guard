# veil

Windows x64 客户端防护库。两种交付形态：header-only 与可选静态库。

核心原则：检测只输出观测值，不输出判定。观测值正常恒为零，作为
HKDF 的 info 参与会话密钥派生。篡改表现为「解不开」，而不是「被拒绝」。

## 构建

    cmake -S . -B build -G Ninja -DVEIL_BUILD_SEED=20261019 -DVEIL_BUILD_TESTS=ON
    cmake --build build
    ctest --test-dir build --output-on-failure

`VEIL_BUILD_SEED` 缺省时回落到构建时间戳并发出警告。正式发版必须显式注入，
否则两次构建的常量可能重合。

## 集成

header-only 形态：

    add_subdirectory(veil)
    target_link_libraries(YourClient PRIVATE veil::header_only)

静态库形态需要额外开启 `-DVEIL_BUILD_STATIC=ON`：

    target_link_libraries(YourClient PRIVATE veil::static)

两种形态可混用。静态库形态只隐藏观测采集与派生链的实现体，
其余部分保持内联。

## 模块

| 层 | 头文件 | 职责 |
|---|---|---|
| L0 | `crypto/sha256` `hmac` `hkdf` `aes` `aes_gcm` `ed25519` | 密码学基座，全部通过标准向量 |
| L1 | `platform/syscall` `peb` `memory` `image_file` `image_map` `decode` `remap` `scan` | 直发系统调用、模块遍历、区间内省、PE 解析、指令解码、代码重映射 |
| L2 | `providers/anti_debug` `code_integrity` `module_topo` `cert_pin` `entropy` | 观测采集，正常环境全部为零 |
| L3 | `evidence/layout` `binder` | 编译期布局序列化与唯一的派生入口 |
| L4 | `license/payload` `envelope` | 可选授权层，时效折算并入功能位 |
| — | `transport/tls_client` `cert_pin` | Schannel 客户端与证书公钥指纹锁定 |
| — | `guard` `static_api` | 装配入口，两种交付形态各一 |

## 观测取代判定

`is_function_hooked`、`MemoryWatchdog::verify_all`、证书指纹比对，三者都是
「先比对、再返回 bool」。这类返回值是单点可改写的：`mov al,1; ret` 即通关。

veil 把校验结果转成密钥材料：

```
info      = 观测字节 ‖ 域
会话密钥  = HKDF-SHA256(ikm=卡密, salt=nonce, info)
```

客户端只知道测到了什么，不知道服务端期望什么。指纹不符、代码被改、
未采集到证据，全部表现为派生分叉，后续 AEAD 认证失败。

## 重映射的边界

`RemappedCode::map_function` 把一段代码复制到原页附近的私有可执行页，
修正基址重定位项与 RIP 相对寻址，并把展开信息登记到新页。

窗口限制来自位移字段宽度：RIP 相对寻址只有 32 位位移，新页与原页的
距离必须落在该范围内。堆区与映像区相距数 TB，因此分配点在原页附近
逐级探测，失败即整体拒绝映射而不是产出无法执行的副本。

解码未覆盖全部字节时同样拒绝映射。未修正的 RIP 引用在运行时会导致
崩溃，静默放过比拒绝更糟。

重映射覆盖的是重定位表能描述的引用与代码段内的 RIP 相对寻址。通过
寄存器间接调用、或经数据段指针跳转的路径仍指向原映像，因此被重映射
的代码不能依赖那些路径访问自身。

## 已知边界

- `scan_code_pages` 的全量地址空间遍历需要约六万次内核查询。结果按
  5 秒窗口缓存于调用线程，需要更严格时序的调用方用
  `invalidate_code_page_cache` 显式失效。
- 外源页统计排除 `MEM_IMAGE` 与 `MEM_MAPPED`：系统存在映像映射的
  可执行页却不登记在 PEB 模块链上，例如 CFG 分发页。计入会使正常
  环境出现非零计数。
- PAGE_GUARD 判据收窄为「可执行且私有且非模块」。每个线程栈都固有
  守卫页，全量计入会让正常环境恒有四到五个。
- `InstructionScanner` 覆盖 x64 常用编码，不追求完整性。无法解码即
  停止并拒绝映射。
- `TlsClient` 只支持 TLS 1.2 与 1.3，不实现会话恢复与 ALPN，也不
  包含应用数据收发。
- `TlsClient` 的 pin 是静态内嵌值。服务端换证书后必须重新探测并
  重新发版。可自动更新的 pin 等于没有 pin。
- 单机防护的天花板：攻击者控制执行环境时可以录制一次合法派生过程
  并复用结果。提高成本的方向是缩短密钥存活时间，而非增加判定点。

## 第三方依赖

`third_party/monocypher` 为 Monocypher 4.0.3 的精简副本，仅保留四个源
文件与许可证。版本、来源与各文件 SHA256 记录在
`third_party/monocypher/README.md`。系统 CNG 不提供 Ed25519，故验签
由 Monocypher 承担；选用 RFC 8032 实现而非 BLAKE2b EdDSA 变体，是因为
服务端 Node `crypto.sign(null, ...)` 产出 SHA-512 版本。
