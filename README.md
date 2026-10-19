# veil

Windows x64 客户端防护库。header-only，无导出符号表。

核心原则：检测只输出观测值，不输出判定。观测值正常恒为零，作为
HKDF 的 info 参与会话密钥派生。篡改表现为「解不开」，而不是「被拒绝」。

## 构建

    cmake -S . -B build -G Ninja -DVEIL_BUILD_SEED=20261019 -DVEIL_BUILD_TESTS=ON
    cmake --build build
    ctest --test-dir build --output-on-failure

`VEIL_BUILD_SEED` 缺省时回落到构建时间戳并发出警告。正式发版必须显式注入，
否则两次构建的常量可能重合。

## 集成

    add_subdirectory(veil)
    target_link_libraries(YourClient PRIVATE veil::header_only)

## 阶段状态

阶段一：密码学基座、syscall 平台层、观测 provider、证据派生、授权信封。
阶段二：执行重映射、PAGE_GUARD 探测、VEH 分析、PIMPL 静态库。
