#pragma once

#include "../config.hpp"
#include "../crypto/sha256.hpp"
#include "../detail/observe.hpp"
#include "../platform/image_file.hpp"

#include <cstddef>
#include <cstdint>

namespace veil::providers {

// 代码完整性观测。
//
// 与 SecCore 的 CRC 度量不同，这里比较磁盘映像与内存映像的摘要差值，
// 而不是内存摘要与内嵌期望值。正常环境下差值为零，因此服务端无需
// 登记任何摘要；改动内存必然让差值非零，要归零只能同时改磁盘文件，
// 那需要重新签名。
//
// region_count 不是判定值：它描述布局，篡改会让后续槽位错位，
// 派生同样分叉。
class CodeIntegrity {
public:
    static constexpr std::size_t MAX_REGIONS = 8;
    static constexpr std::size_t DIGEST_SIZE = 32;
    static constexpr std::size_t OBSERVATION_SIZE =
        sizeof(std::uint32_t) + MAX_REGIONS * DIGEST_SIZE;

    struct ObservationBuffer {
        std::uint32_t region_count;
        std::uint8_t deltas[MAX_REGIONS][DIGEST_SIZE];
    };

    static_assert(sizeof(ObservationBuffer) == OBSERVATION_SIZE,
                  "observation buffer must be tightly packed");

    // 登记当前模块的全部可执行段。磁盘侧与内存侧成对登记。
    bool register_module_sections() noexcept {
        if (!image_.open_self())
            return false;

        const std::size_t count = image_.section_count();
        for (std::size_t i = 0; i < count && region_count_ < MAX_REGIONS; ++i) {
            platform::SectionView section{};
            if (!image_.section_at(i, &section))
                continue;
            if (!section.executable || section.raw_size == 0)
                continue;
            region_sections_[region_count_++] = i;
        }
        return region_count_ > 0;
    }

    // 手工登记一对同源指针。磁盘侧与内存侧长度相同，差值由内容决定。
    // 供无法读取磁盘映像的场景使用，也供测试注入。
    bool register_region_manual(const void* disk_bytes,
                                const void* memory_bytes,
                                std::size_t size = sizeof(std::uint64_t)) noexcept {
        if (region_count_ >= MAX_REGIONS || disk_bytes == nullptr ||
            memory_bytes == nullptr || size == 0)
            return false;

        manual_regions_[region_count_] = {disk_bytes, memory_bytes, size};
        region_sections_[region_count_] = MANUAL_MARKER;
        ++region_count_;
        return true;
    }

    std::size_t region_count() const noexcept { return region_count_; }

    Observation observe() const noexcept {
        buffer_ = ObservationBuffer{};
        buffer_.region_count = static_cast<std::uint32_t>(region_count_);

        for (std::size_t i = 0; i < region_count_; ++i) {
            std::uint8_t disk_digest[DIGEST_SIZE]{};
            std::uint8_t memory_digest[DIGEST_SIZE]{};

            if (region_sections_[i] == MANUAL_MARKER) {
                const ManualRegion& region = manual_regions_[i];
                Sha256::hash(region.disk_bytes, region.size, disk_digest);
                Sha256::hash(region.memory_bytes, region.size, memory_digest);
            } else {
                const std::size_t index = region_sections_[i];
                if (!image_.digest_disk(index, disk_digest))
                    continue;
                if (!image_.digest_memory(index, memory_digest))
                    continue;
            }

            for (std::size_t k = 0; k < DIGEST_SIZE; ++k)
                buffer_.deltas[i][k] =
                    static_cast<std::uint8_t>(disk_digest[k] ^ memory_digest[k]);

            detail::secure_wipe(disk_digest, sizeof(disk_digest));
            detail::secure_wipe(memory_digest, sizeof(memory_digest));
        }

        // 测试注入的合成差值叠加在实测值上，保证观测链路真的会带出槽位内容
        for (std::size_t i = 0; i < MAX_REGIONS; ++i)
            buffer_.deltas[i][0] ^= synthetic_[i];

        return Observation{&buffer_, OBSERVATION_SIZE};
    }

    // 测试专用：写入合成差值，验证观测链路会把它带出来。
    bool inject_delta_for_test(std::size_t index, std::uint8_t value) noexcept {
        if (index >= MAX_REGIONS)
            return false;
        synthetic_[index] = value;
        return true;
    }

private:
    static constexpr std::size_t MANUAL_MARKER = static_cast<std::size_t>(-1);

    struct ManualRegion {
        const void* disk_bytes;
        const void* memory_bytes;
        std::size_t size;
    };

    mutable platform::ImageFile image_;
    std::size_t region_count_ = 0;
    std::size_t region_sections_[MAX_REGIONS]{};
    ManualRegion manual_regions_[MAX_REGIONS]{};
    std::uint8_t synthetic_[MAX_REGIONS]{};
    mutable ObservationBuffer buffer_{};
};

static_assert(ProviderLike<CodeIntegrity>);

}  // namespace veil::providers
