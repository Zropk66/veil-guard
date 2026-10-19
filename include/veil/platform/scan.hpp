#pragma once

#include "../config.hpp"
#include "../detail/mix.hpp"
#include "memory.hpp"
#include "peb.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::platform {

// 判断地址归属的模块基址。未归属任何模块时返回 nullptr。
inline void* module_base_of(const void* address) noexcept {
    const std::size_t count = module_count();
    const auto target = reinterpret_cast<std::uintptr_t>(address);

    for (std::size_t i = 0; i < count; ++i) {
        ModuleInfo info{};
        if (!module_at(i, &info))
            continue;
        const auto begin = reinterpret_cast<std::uintptr_t>(info.base);
        if (target >= begin && target < begin + info.size)
            return info.base;
    }
    return nullptr;
}

namespace detail {

// 模块区间快照。扫描内每个区间都要做归属判定，逐次遍历 PEB 模块链
// 是二次复杂度；这里一次性取出区间数组，判定退化为线性查找。
struct ModuleRanges {
    struct Range {
        std::uintptr_t begin;
        std::uintptr_t end;
    };

    static constexpr std::size_t MAX_MODULES = 512;

    Range ranges[MAX_MODULES]{};
    std::size_t count = 0;

    void load() noexcept {
        count = 0;
        const std::size_t modules = module_count();
        for (std::size_t i = 0; i < modules && count < MAX_MODULES; ++i) {
            ModuleInfo info{};
            if (!module_at(i, &info))
                continue;
            const auto begin = reinterpret_cast<std::uintptr_t>(info.base);
            ranges[count].begin = begin;
            ranges[count].end = begin + info.size;
            ++count;
        }
    }

    bool owns(std::uintptr_t address) const noexcept {
        for (std::size_t i = 0; i < count; ++i)
            if (address >= ranges[i].begin && address < ranges[i].end)
                return true;
        return false;
    }
};

// 单次地址空间遍历同时收集两类特征。分开扫描会让每次派生付出两倍
// 的遍历成本，而这两项特征本就来自同一批区间。
struct ScanResult {
    std::uint32_t foreign_executable_pages;
    std::uint8_t foreign_address_hash[16];
    std::uint32_t guarded_executable_pages;
    std::uint64_t guard_hash;
};

inline void scan_regions(ScanResult* result) noexcept {
    result->foreign_executable_pages = 0;
    result->guarded_executable_pages = 0;
    result->guard_hash = 0;
    for (std::size_t i = 0; i < 16; ++i)
        result->foreign_address_hash[i] = 0;

    ModuleRanges modules;
    modules.load();

    RegionWalker walker;
    RegionInfo info{};

    while (walker.next(&info)) {
        if (!is_committed(info) || !is_executable(info))
            continue;
        if (info.type != MEM_PRIVATE)
            continue;
        if (modules.owns(reinterpret_cast<std::uintptr_t>(info.base)))
            continue;

        const auto address = reinterpret_cast<std::uint64_t>(info.base);
        const std::uint64_t mixed = veil::detail::mix64(address);

        ++result->foreign_executable_pages;
        for (std::size_t b = 0; b < 16; ++b)
            result->foreign_address_hash[b] ^=
                static_cast<std::uint8_t>(mixed >> ((b % 8) * 8));

        if (is_guarded(info)) {
            ++result->guarded_executable_pages;
            result->guard_hash ^= veil::detail::mix64(address ^ info.protect);
        }
    }
}

}  // namespace detail

// 外源可执行区间与可执行守卫页统计。
//
// 注入的代码无论走 LoadLibrary、手工映射还是 shellcode，最终都必须
// 落在可执行页上。系统模块自身的可执行页是映像映射，私有可执行页
// 只可能来自 JIT 运行时与注入代码，因此「不在任何已加载模块内的
// 可执行私有提交页」是一个与注入强相关、且正常环境恒为零的特征。
//
// 必须排除 MEM_IMAGE。系统存在若干映像映射的可执行页却不登记在
// PEB 模块链上，例如 CFG 的分发页与只读共享节；把它们计入会让
// 正常环境出现非零计数，破坏零值基线。MEM_MAPPED 同理排除：
// 它来自文件映射，不属于运行时生成的代码。
//
// PAGE_GUARD 单独看不足以构成特征：每个线程栈都固有守卫页，正常
// 环境恒有四到五个。判据收窄为「可执行且私有且非模块」的守卫页，
// 即调试器挂钩代码页的情形，收窄后未篡改环境下计数为零。
//
// 输出的是计数与地址哈希累积，不是判定值。
struct ForeignCodePages {
    std::uint32_t foreign_count;
    std::uint32_t guarded_count;
    std::uint8_t foreign_address_hash[16];
    std::uint64_t guard_hash;
};

// 丢弃缓存，使下一次采集重新遍历地址空间。供调用方在关键时点
// 强制刷新，例如收到服务端挑战、进入敏感流程之前。
inline void invalidate_code_page_cache() noexcept;

struct CodePageCache {
    ForeignCodePages pages{};
    std::uint64_t stamp = 0;
    bool valid = false;

    static CodePageCache& instance() noexcept {
        static thread_local CodePageCache slot;
        return slot;
    }
};

inline void scan_code_pages(ForeignCodePages* out) noexcept {
    // 全量遍历需要约 65682 次内核查询、耗时 200ms 以上，无法在每次
    // 派生时重复。缓存窗口取 5 秒：正常派生模式是会话开始时连续
    // 派生数次，之后长时间复用同一密钥，因此窗口覆盖了整个启动
    // 阶段。窗口到期后的首次派生会重新扫描，注入若发生在窗口内，
    // 下一次刷新即可见。需要更严格时序的调用方用
    // invalidate_code_page_cache 显式失效。
    constexpr std::uint64_t CACHE_WINDOW_MS = 5000;

    CodePageCache& cache = CodePageCache::instance();

    LARGE_INTEGER frequency{};
    LARGE_INTEGER now{};
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&now);

    const std::uint64_t ticks =
        static_cast<std::uint64_t>(now.QuadPart);
    const std::uint64_t window =
        static_cast<std::uint64_t>(frequency.QuadPart) *
        CACHE_WINDOW_MS / 1000;

    if (cache.valid && ticks - cache.stamp < window) {
        *out = cache.pages;
        return;
    }

    detail::ScanResult result{};
    detail::scan_regions(&result);

    cache.pages.foreign_count = result.foreign_executable_pages;
    cache.pages.guarded_count = result.guarded_executable_pages;
    cache.pages.guard_hash = result.guard_hash;
    for (std::size_t i = 0; i < 16; ++i)
        cache.pages.foreign_address_hash[i] = result.foreign_address_hash[i];

    cache.stamp = ticks;
    cache.valid = true;

    *out = cache.pages;
}

inline void invalidate_code_page_cache() noexcept {
    // 缓存是 thread_local；失效只作用于调用线程。
    // 其余线程各自持有独立缓存，各自到期后刷新。
    CodePageCache::instance().valid = false;
}

inline std::uint32_t scan_foreign_executable_pages(
    std::uint8_t address_hash[16]) noexcept {
    ForeignCodePages pages{};
    scan_code_pages(&pages);
    if (address_hash != nullptr)
        for (std::size_t i = 0; i < 16; ++i)
            address_hash[i] = pages.foreign_address_hash[i];
    return pages.foreign_count;
}

inline std::uint32_t scan_guard_pages(std::uint64_t* region_hash) noexcept {
    ForeignCodePages pages{};
    scan_code_pages(&pages);
    if (region_hash != nullptr)
        *region_hash = pages.guard_hash;
    return pages.guarded_count;
}

}  // namespace veil::platform
