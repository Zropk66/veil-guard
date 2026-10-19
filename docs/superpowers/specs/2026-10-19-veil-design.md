# veil 设计规格

Windows x64 客户端防护库。取代 SecCore 在客户端侧的防护职责，
修正其既有缺陷，并把「检测结果不进入判定、只进入密钥材料」这一原则
推广到全部检测项。

## 定位与边界

`veil` 是通用防护库，对具体业务零依赖。授权协议的载荷结构、HWID 算法、
证据期望值全部由接入方提供。库只负责：

- 采集原始观测值
- 规范编码观测值
- 以观测值为 `info` 派生会话密钥

库不负责：判断环境是否可信、决定是否放行、定义授权语义。

### 与 SecCore 的关系

新建独立项目，不修改 SecCore。SecCore 继续可用。`veil` 不继承下列缺陷：

| SecCore 缺陷 | veil 的处理 |
|---|---|
| `build_seed()` 月份不参与派生，取值空间坍缩至约 400 种 | 完整 `__DATE__` 与 `__TIME__` 参与，且 CMake 强制注入 `VEIL_BUILD_SEED` |
| `PoisonSink::register_slot` 超出 `MAX_SLOTS` 时索引越界 | 不提供可写槽位，观测只做累积 |
| `TlsTransport::recv_all` 的 `pending` 为 `static thread_local` | 改为实例成员 |
| `derive_machine_key` 对超长机器标识静默降级为空标识 | 显式失败 |
| `ModuleAudit::is_path_trusted` 对路径做任意位置子串匹配 | 前缀匹配与同目录判定 |
| `Guard::Report::watchdog_armed` 从未被赋值 | 不进入新接口 |
| `CngApi::instance` 的 `static bool attempted` 非原子 | `std::call_once` |
| `Guard::derive_session_key` 与 `EvidenceBinder::derive` 两套派生并存 | 只保留一条派生路径 |

## 交付形态

核心全部为 header-only，内联进调用方，无导出符号表。另提供可选的
PIMPL 静态库 target，用于需要隐藏实现的接入方。两者共用同一套源。

构建系统为 CMake，不生成 `.vcxproj`。

平台范围：Windows x64。不做跨平台抽象，不提供 x86 支持。

密码学：对称算法、哈希与 KDF 自行实现；Ed25519 与 X25519 使用
vendored Monocypher 4.0.3 的 RFC 8032 实现。

## 分层

```
L0  crypto      AES-256-GCM / SHA-256 / HMAC / HKDF / Ed25519
L1  platform    syscall 直发 / PEB 遍历 / 内存内省 / 磁盘映像读取 / 机器标识
L2  providers   反调试 · 完整性 · 模块拓扑 · 证书指纹 · 熵源
L3  evidence    观测聚合 → 规范编码 → HKDF(info) → 会话密钥
L4  optional    签名信封（Ed25519 + AES-256-GCM）
```

依赖方向单向向下。L2 只依赖 L0 与 L1，L3 只依赖 L0 与 L2 的观测，
L4 只依赖 L0 与 L3。模块之间不共享可变状态。

## 核心原则：观测值代替判定值

SecCore 仅在 `EvidenceBinder` 一处做到「实测值进密钥而非是非量」，
其余检测仍返回 `bool`。`bool` 是单字节可改写的东西，`mov al,1; ret` 即通关。

`veil` 把该原则变成硬约束：**L2 的 provider 只输出原始观测字节，
永不输出判定结果，且正常环境下这些字节恒为零值。**

布尔量进证据等价于布尔判定换了个存放位置：攻击者改那一字节，
派生即对齐。因此观测结构必须满足：

- 字段取值在未篡改环境下可预测，且为常量（通常为全零）
- 篡改任一字段都会让结构偏离该常量，进而使派生分叉
- 服务端无需登记正常值，只需验证派生是否成立

### 各 provider 的观测结构

反调试：

```
AntiDebugSnapshot {
    uint8_t  being_debugged;        // 正常 0
    uint32_t nt_global_flag;        // 正常 0
    uint8_t  hardware_breakpoints;  // Dr0-Dr3 中非零数量，正常 0
    uint32_t page_guard_events;     // 正常 0
    uint32_t veh_foreign_handlers;  // 非系统模块注册的 VEH 数量，正常 0
}
```

攻击者要让派生成立，必须让全部字段同时回到零值，等价于根本不调试。

模块拓扑：

```
ForeignModuleDigest {
    uint32_t foreign_count;         // 不可信路径模块数，正常 0
    uint8_t  path_hash_xor[16];     // 各模块路径哈希的累积，正常全零
}
```

代码完整性：

```
CodeIntegrity {
    uint32_t region_count;                    // 已登记区域数
    uint8_t  disk_vs_memory[8][32];           // 每区域磁盘摘要 XOR 内存摘要，正常全零
    uint8_t  unused[8 - region_count][32];    // 未登记区域填零
}
```

`region_count` 本身不是判定值：它只描述布局，篡改它会让后续区域错位，
派生同样分叉。

取磁盘映像与内存的差值，而非内存摘要本身。SecCore 要求每次发版在服务端
登记代码段摘要，否则全体客户端派生分叉；差值恒为零，服务端零登记。
让差值归零必须同时篡改磁盘文件，那需要重新签名。

证书指纹 provider 只做实测，不内嵌预期值。服务端以自己的证书做同样的
派生，因此同样不需要登记。全部证据项的正常值都由服务端自行复现，
不存在需要运维同步的登记表。

## Provider 契约

```cpp
namespace veil {

struct Observation {
    const void* data;
    std::size_t size;
};

template <typename Provider>
concept ProviderLike = requires {
    { Provider::OBSERVATION_SIZE } -> std::convertible_to<std::size_t>;
    { Provider::observe() } -> std::same_as<Observation>;
};

}
```

消费者按声明顺序组合：

```cpp
using Evidence = veil::evidence::Layout<
    veil::providers::CertificatePin,
    veil::providers::CodeIntegrity,
    veil::providers::AntiDebugSnapshot,
    veil::providers::ForeignModuleDigest>;
```

`Layout::serialize(buffer)` 按顺序拼接，产出固定长度 blob，作为 HKDF 的
`info`。顺序与内容在编译期确定，无运行时分发、无中心表。

派生：

```
会话密钥 = HKDF-SHA256(ikm = 授权密钥, salt = nonce, info = blob ‖ domain)
```

domain 字节区分同一观测下的不同用途密钥。客户端只知其测得什么，
不知服务端期望什么；服务端以自己知道的值复现同一 `info`，两侧一致才能
派生出同一密钥。指纹不符、代码段被改、未采集到观测，全部表现为派生分叉，
后续 AEAD 认证失败。

## L1 platform

```
Syscall      x64 syscall 直发；SSN 由 ntdll 导出表排序推导；
             对已被改写的 stub 用相邻 stub 做交叉验证
Peb          结构化遍历模块链取基址与路径，不引用 IAT
MemoryQuery  NtQueryVirtualMemory 取代 VirtualQuery
ImageFile    按磁盘读取自身 PE，解析 section header 取 .text 原始字节
```

`Syscall` 是其余三块的基础。SecCore 仅 `CngApi` 部分走动态解析，
`ModuleAudit` 与 `MemoryWatchdog` 仍直接引用 IAT，改写 `VirtualQuery`
槽位即可让注入栈扫描失效。`veil` 把全部系统调用下沉到 syscall 直发。

`MemoryQuery` 用于 `PAGE_GUARD` 重定向探测与区间属性内省。

`ImageFile` 用于完整性 provider 取磁盘侧原始字节。读取自身磁盘映像需
处理 UWP 打包与内存映像两种装载形式，由 `ImageFile` 内部统一。

## L2 providers

```
AntiDebugSnapshot    PEB 标志、硬件断点寄存器、PAGE_GUARD 事件、
                     VEH 处理器归属审计
CodeIntegrity        区域登记、重映射为私有可执行页、
                     磁盘与内存双源摘要、周期性度量
ForeignModuleDigest  模块链遍历，系统目录与同目录之外计为外源
CertificatePin       对端 SPKI 指纹实测，不与预期值比对
Entropy              ChaCha20 DRBG，四路物理熵混合
```

完整性 provider 借鉴 UltimateAntiCheat 的 `remap.cpp` 思路：把 `.text`
重映射为私有可执行页。这同时解决两件事：

- 按 RVA 下断点的常规手段失效，因为代码不再位于原 RVA
- 度量对象是私有页，摘要不再被自度量循环污染

`AntiDebugSnapshot` 借鉴 NotRequiem/antidbg 的检测面，但输出观测而非布尔。
检测项包含：`PAGE_GUARD` 重定向行为、VEH 与 SEH 投递分析、
硬件断点寄存器读取、入口点 TLS callback 保护。

## L4 授权信封（可选层）

载荷对库不透明。库不定义字段语义，只要求长度与序列化器：

```cpp
struct MyLicense {
    std::uint64_t expires_at;
    std::uint32_t feature_mask;
};
static_assert(veil::license::PayloadLike<MyLicense>);
```

协议形状：

```
info     = 证据 ‖ HWID长度 ‖ HWID ‖ 域
会话密钥 = HKDF-SHA256(ikm=卡密, salt=nonce, info)
AAD      = issued_at ‖ nonce ‖ 域
信封     = issued_at ‖ nonce ‖ AES-256-GCM(会话密钥, AAD, 载荷) ‖ 标签
签名     = Ed25519(信封全部字节)   服务端私钥
```

HWID 与证据都是派生输入，不做独立比对。不符时派生出另一把密钥，
标签校验失败，不存在「机器是否匹配」这样可单点 patch 的分支。

处理顺序为验签 → 时间窗 → 派生 → 解密。验签只需公钥，是纯公开计算，
放在最前让垃圾输入在接触解密器之前被挡住，不给解密 oracle。

服务端侧的证据输入必须是它自己知道的零基线，不能照抄客户端上报的值。
照抄会让攻击者把篡改后测到的非零证据一并发来，两侧仍派生同一把密钥。
上报值只用于记录。

时效折算由消费者侧完成，库提供模板钩子：

```cpp
const std::uint32_t mask = veil::license::effective_mask(payload, now_ms);
```

不提供独立的过期检查接口。单一判定点正是被 patch 的目标。

## 失败处置

全链路证据派生，不提供硬失败钩子，不主动崩溃。

篡改的表现是「解不开」而非「被拒绝」。这不是不可破，是把
「找一处跳转」变成「复刻整条派生链」。

## 已知边界

- 单机防护天花板：攻击者控制执行环境时，可录制一次合法派生过程复用结果，
  也可在合法机器上直接读取派生出的正确密钥。提高成本的方向是缩短密钥
  存活时间，而非增加判定点。
- `CodeIntegrity` 的重映射在 JIT 生成的代码页上不适用。
- 磁盘映像不可读时，`CodeIntegrity` 输出零值，与未篡改环境的观测相同，
  等价于该 provider 不参与派生。这是刻意的：让「采集失败」成为可观测的
  拒绝，等于给出一个判定点。
- 证书指纹 provider 只做一次实测，不内嵌预期值，因此不存在换证书后
  需要重新发版的问题。内嵌 pin 只出现在显式调用 `connect_to` 的传输路径，
  与证据链无关。若接入方选择使用内嵌 pin 的传输层，则换证书后需重新发版；
  这是该路径自身的取舍，不影响证据 provider。
- 熵源在禁用 `RDRAND` 的虚拟化环境中退化为三路混合。
- TLS 仅支持 1.2 与 1.3，不实现会话恢复与 ALPN。
- HTTP 客户端只解析定长与分块两种传输编码，不处理重定向与连接复用。
- 机器标识的 SMBIOS 来源在部分虚拟机与主板上为空，此时退化为两路混合。
  三者全不可用才失败。
- HWID 上限 127 字节。超出显式失败，不截断。
- 授权信封单条签名消息上限 8192 字节，超出显式失败。
- `Guard` 的装配点受 DllMain 的加载器锁约束。默认装配不做任何文件读取
  或加密初始化，这些工作推迟到首次派生调用时执行。
- 证据 provider 的正常值必须恒为零。模块拓扑与证书指纹不满足该条件，
  因此都不在任何已登记布局内。

## 测试

| 类别 | 内容 |
|---|---|
| 标准向量 | AES-256 FIPS-197、AES-256-GCM NIST SP 800-38D 四组、SHA-256、Ed25519 RFC 8032 |
| 跨实现 | Node 生成夹具，C++ 侧逐字节比对，覆盖证据编码与信封往返 |
| 篡改分叉 | 内存打补丁后断言派生密钥必然变化 |
| 零值基线 | 无篡改环境下全部观测结构逐字节为零，验证「服务端零登记」成立 |
| 重映射 | remap 后磁盘与内存摘要相等、patch 后不等 |

跨实现测试需要两侧就 `Layout` 的序列化顺序达成一致。该顺序由消费者
声明决定，因此两侧共用一份声明文件，或在接入方侧手工保持同步。
库不提供自动生成器。

「零值基线」用于直接验证观测结构满足核心原则。SecCore 没有该测试，
因为其摘要本身就不是零值。

测试判据统一为「相同输入派生相同密钥、任一字段改动派生必然分叉」，
不测「是否返回 true」。

## 集成

```cmake
add_subdirectory(veil)
target_link_libraries(YourClient PRIVATE veil::header_only)
# 或隐藏实现：
target_link_libraries(YourClient PRIVATE veil::static)
```

装配：

```cpp
#include <veil/veil.hpp>

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        veil::Guard guard;
        guard.arm<Evidence>(card_key, card_key_len);
    }
    return TRUE;
}
```

环境不可信时不阻断初始化，改为让后续派生分叉。业务代码在协议解析阶段
自然失败，不给调用方提供判定结果。
