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
| L1 | `platform/syscall` `peb` `memory` `image_file` `image_map` `decode` `remap` `scan` `hwid` | 直发系统调用、模块遍历、区间内省、PE 解析、指令解码、代码重映射、机器标识 |
| L2 | `providers/anti_debug` `code_integrity` `module_topo` `cert_pin` `entropy` | 观测采集，正常环境全部为零 |
| L3 | `evidence/layout` `binder` | 编译期布局序列化与唯一的派生入口 |
| L4 | `license/payload` `signed_envelope` | 可选授权层，时效折算并入功能位 |
| — | `transport/tls_client` `cert_pin` `http` `license_client` | Schannel 客户端、证书公钥指纹锁定、HTTP/1.1 分帧与授权接口封装 |
| — | `guard` `static_api` | 装配入口，两种交付形态各一 |

入库的 provider 不都进默认布局。只有 `anti_debug` 与 `code_integrity` 的
正常值恒为零，能配合服务端的零基线。`module_topo` 与 `cert_pin` 另有用处，
但正常值不是零，接入方自行装配时须在服务端登记期望值。

## 布局契约

| 标识 | 长度 | 组成 |
|---|---|---|
| `1` | 16 | `AntiDebugSnapshot` |
| `2` | 276 | 布局 1 加 `CodeIntegrity` |

客户端在请求中声明 `evidenceLayout`，服务端按该标识取零基线长度。标识与
长度任一处改动都必须两侧同时发布。

## 对接服务端

`transport/license_client` 把一次验证拆成可替换的三段：构造请求、收发、
解析响应。没有内嵌重试、没有后台线程、没有全局状态。

```cpp
veil::transport::LicenseClient client;
veil::transport::CertPin pin(server_spki_digest);
if (!client.connect(host, 443, pin)) return;

char nonce[32];
guard.next_nonce(nonce, sizeof(nonce));

char response[64 * 1024];
veil::transport::LicenseClient::Response meta{};
if (!client.exchange({host, "/api/license-verification/veil",
                      body, body_length}, response, sizeof(response), &meta))
    return;
```

响应中的信封字段用 `JsonScanner` 在原始文本上取区间，不解析成对象再重新
序列化。服务端签名覆盖 `JSON.stringify` 的精确字节，重新编码会让键序与
转义不一致，验签永久失败。

机器标识由 `platform::MachineId` 采集：系统 MachineGuid、系统盘卷序列号、
SMBIOS System UUID 三者拼接后取 SHA-256，输出 32 位十六进制。任一来源
缺失时以零填充参与摘要，长度不变。

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
修正基址重定位项与 RIP 相对寻址，把 `.xdata` 展开信息一并复制进新页，
并把表项登记到新页基址。

窗口限制来自位移字段宽度：RIP 相对寻址只有 32 位位移，新页与原页的
距离必须落在该范围内。堆区与映像区相距数 TB，因此分配点在原页附近
逐级探测，失败即整体拒绝映射而不是产出无法执行的副本。

函数边界不取自 `.pdata` 的 `EndAddress`。编译器会把尾部的 `ret` 合并到
相邻函数，条目结束于 `ret` 之前；短跳转也可能越过自己的 `ret` 落到相邻
代码块。按条目长度复制出的副本执行到末尾会冲进零填充。因此边界由解码
扫描得出，覆盖到最后一条返回指令与最远分支目标。叶子函数没有 `.pdata`
条目，走的也是这条路径。

解码未覆盖全部字节时拒绝映射。未修正的 RIP 引用在运行时会导致崩溃，
静默放过比拒绝更糟。

重映射覆盖的是重定位表能描述的引用与代码段内的 RIP 相对寻址及相对
`call`/`jmp`。通过寄存器间接调用、或经数据段指针跳转的路径仍指向原映像，
因此被重映射的代码不能依赖那些路径访问自身。

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
- `ModuleTopology` 的同目录判定要求目录完全一致。客户端装在多层目录
  下时，子目录内的自有模块会被计为外源。它不参与默认布局，接入方
  使用前须确认自己的模块分布。
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

Monocypher 以 BSD-2-Clause 授权，该条款独立适用，不受本仓库的授权
声明影响。

## 授权

私有项目，保留全部权利。未授予任何使用、复制、修改或分发许可。
