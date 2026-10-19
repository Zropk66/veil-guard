#pragma once

#include "../config.hpp"
#include "../detail/observe.hpp"
#include "../platform/peb.hpp"
#include "../platform/scan.hpp"
#include "../platform/syscall.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::providers {

// 反调试观测。
//
// 与常规反调试库的区别：这里不返回「是否被调试」。字段是原始计数，
// 正常环境全为零，直接作为 HKDF 的 info 参与派生。攻击者要让派生成立，
// 必须让全部字段同时回到零值，等价于根本不调试。
//
// 没有可比对的布尔量，也就没有可单点改写的跳转。
struct AntiDebugSnapshot {
    std::uint8_t being_debugged{};
    std::uint8_t hardware_breakpoints{};
    // NtQueryInformationProcess 的 ProcessDebugObjectHandle 命中次数。
    // 查的是内核里的调试对象，不是可写的 PEB 字段，抹掉 BeingDebugged
    // 不影响这一项。
    std::uint8_t debug_object_present{};
    // ProcessDebugFlags 返回 0 的命中次数。正常进程该值为 1。
    std::uint8_t debug_flags_cleared{};
    std::uint32_t nt_global_flag{};
    std::uint32_t foreign_executable_pages{};
    std::uint32_t page_guard_events{};

    static constexpr std::size_t OBSERVATION_SIZE = 16;

    static Observation observe() noexcept {
        static thread_local AntiDebugSnapshot snapshot;
        snapshot = capture();
        return Observation{&snapshot, OBSERVATION_SIZE};
    }

    static AntiDebugSnapshot capture() noexcept {
        AntiDebugSnapshot snapshot{};

        PPEB p = platform::peb();
        if (p != nullptr) {
            snapshot.being_debugged = p->BeingDebugged;
            snapshot.nt_global_flag = read_global_flag(p) & DEBUG_FLAGS_MASK;
        }

        snapshot.hardware_breakpoints = count_hardware_breakpoints();
        snapshot.debug_object_present = probe_debug_object();
        snapshot.debug_flags_cleared = probe_debug_flags();

        // 注入代码最终必须落在私有可执行页上，调试器则会在代码页挂
        // PAGE_GUARD。两者在未篡改环境下恒为零，因此可以直接作为
        // 派生的 info，不需要服务端登记期望值。
        platform::ForeignCodePages pages{};
        platform::scan_code_pages(&pages);

        snapshot.foreign_executable_pages = pages.foreign_count;
        snapshot.page_guard_events = pages.guarded_count;

        return snapshot;
    }

private:
    static constexpr std::uint32_t DEBUG_FLAGS_MASK = 0x70u;

    // 未附加调试对象时 ProcessDebugObjectHandle 的返回状态
    static constexpr long STATUS_PORT_NOT_SET = 0xC0000353L;

    // ProcessDebugObjectHandle。附加调试器时该查询成功并返回句柄，
    // 否则返回 STATUS_PORT_NOT_SET。
    static std::uint8_t probe_debug_object() noexcept {
        std::uintptr_t handle = 0;
        const long status = query_process(0x1E, &handle);
        if (status != STATUS_PORT_NOT_SET)
            return 1;
        return handle != 0 ? 1 : 0;
    }

    // ProcessDebugFlags。正常进程返回 1，附加调试器后归零。
    static std::uint8_t probe_debug_flags() noexcept {
        std::uintptr_t flags = 1;
        const long status = query_process(0x1F, &flags);
        if (status != 0)
            return 0;
        return flags == 0 ? 1 : 0;
    }

    static long query_process(std::uint32_t info_class,
                              std::uintptr_t* out) noexcept {
        const std::uint32_t ssn =
            platform::syscall_number("NtQueryInformationProcess");
        if (ssn == 0)
            return -1;

        std::uintptr_t value = 0;
        const long status = platform::syscall_direct(
            ssn,
            static_cast<std::uintptr_t>(
                reinterpret_cast<std::uintptr_t>(GetCurrentProcess())),
            static_cast<std::uintptr_t>(info_class),
            reinterpret_cast<std::uintptr_t>(&value),
            sizeof(value),
            0,
            0);
        if (status == 0)
            *out = value;
        return status;
    }

    static std::uint32_t read_global_flag(const PPEB p) noexcept {
        // NtGlobalFlag 在 x64 下位于 PEB + 0xBC。该偏移在 Win7 之后稳定。
        const auto* flags = reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<std::uintptr_t>(p) + 0xBC);
        return *flags;
    }

    // 硬件断点不需要改任何代码，因此不会触发完整性校验，只能通过 Dr
    // 寄存器发现。RtlCaptureContext 不填充调试寄存器，必须走
    // NtGetContextThread 直发；两者都会命中内核对当前线程的处理，
    // 因此不复用 kernel32 的 GetThreadContext 导出。
    static std::uint8_t count_hardware_breakpoints() noexcept {
        const std::uint32_t ssn =
            platform::syscall_number("NtGetContextThread");
        if (ssn == 0)
            return 0;

        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        const long status = platform::syscall_direct(
            ssn,
            static_cast<std::uintptr_t>(
                reinterpret_cast<std::uintptr_t>(GetCurrentThread())),
            reinterpret_cast<std::uintptr_t>(&context),
            0,
            0,
            0,
            0);
        if (status != 0)
            return 0;

        std::uint8_t count = 0;
        if (context.Dr0 != 0) ++count;
        if (context.Dr1 != 0) ++count;
        if (context.Dr2 != 0) ++count;
        if (context.Dr3 != 0) ++count;
        return count;
    }
};

static_assert(sizeof(AntiDebugSnapshot) == AntiDebugSnapshot::OBSERVATION_SIZE,
              "observation layout must stay stable");
static_assert(ProviderLike<AntiDebugSnapshot>);

}  // namespace veil::providers
