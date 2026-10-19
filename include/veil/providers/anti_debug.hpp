#pragma once

#include "../config.hpp"
#include "../detail/observe.hpp"
#include "../platform/peb.hpp"
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
    std::uint8_t reserved0{};
    std::uint8_t reserved1{};
    std::uint32_t nt_global_flag{};
    std::uint32_t veh_foreign_handlers{};
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
        return snapshot;
    }

private:
    static constexpr std::uint32_t DEBUG_FLAGS_MASK = 0x70u;

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
