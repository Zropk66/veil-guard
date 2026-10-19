#pragma once

#include "../config.hpp"
#include "../crypto/sha256.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::platform {

struct SectionView {
    const char* name;
    std::uint32_t virtual_address;
    std::uint32_t virtual_size;
    std::uint32_t raw_offset;
    std::uint32_t raw_size;
    std::uint32_t characteristics;
    bool executable;
};

// 按磁盘读取自身 PE 映像，供完整性 provider 取 .text 原始字节。
//
// 内存映像可能已被改写，磁盘侧则只有修改文件才能改变，而修改文件
// 需要重新签名。两者摘要的差值因此是一个可信度更高的基线。
class ImageFile {
public:
    bool open_self() noexcept {
        const HMODULE module = GetModuleHandleA(nullptr);
        if (module == nullptr)
            return false;
        return open_module(module);
    }

    bool open_module(void* base) noexcept {
        close();
        if (base == nullptr)
            return false;

        image_base_ = base;

        char path[MAX_PATH];
        const DWORD length = GetModuleFileNameA(static_cast<HMODULE>(base),
                                                path, MAX_PATH);
        if (length == 0 || length >= MAX_PATH) {
            image_base_ = nullptr;
            return false;
        }

        file_ = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) {
            image_base_ = nullptr;
            return false;
        }

        const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            close();
            return false;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const std::uint8_t*>(base) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            close();
            return false;
        }

        const IMAGE_FILE_HEADER& header = nt->FileHeader;
        if (header.NumberOfSections == 0 ||
            header.NumberOfSections > MAX_SECTIONS) {
            close();
            return false;
        }

        const IMAGE_SECTION_HEADER* raw = IMAGE_FIRST_SECTION(nt);
        section_count_ = header.NumberOfSections;
        for (std::size_t i = 0; i < section_count_; ++i) {
            sections_[i].name = reinterpret_cast<const char*>(raw[i].Name);
            sections_[i].virtual_address = raw[i].VirtualAddress;
            sections_[i].virtual_size = raw[i].Misc.VirtualSize;
            sections_[i].raw_offset = raw[i].PointerToRawData;
            sections_[i].raw_size = raw[i].SizeOfRawData;
            sections_[i].characteristics = raw[i].Characteristics;
            sections_[i].executable =
                (raw[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        }

        return true;
    }

    void close() noexcept {
        if (file_ != INVALID_HANDLE_VALUE) {
            CloseHandle(file_);
            file_ = INVALID_HANDLE_VALUE;
        }
        image_base_ = nullptr;
        section_count_ = 0;
    }

    ~ImageFile() noexcept { close(); }

    ImageFile() = default;
    ImageFile(const ImageFile&) = delete;
    ImageFile& operator=(const ImageFile&) = delete;

    bool loaded() const noexcept { return file_ != INVALID_HANDLE_VALUE; }
    void* image_base() const noexcept { return image_base_; }
    std::size_t section_count() const noexcept { return section_count_; }

    bool section_at(std::size_t index, SectionView* out) const noexcept {
        if (out == nullptr || index >= section_count_)
            return false;
        *out = sections_[index];
        return true;
    }

    // 磁盘侧摘要。段在文件中按 FileAlignment 对齐，尾部填充不属于
    // 内存映像，故与内存侧统一取 min(SizeOfRawData, VirtualSize)，
    // 两侧覆盖同一段逻辑字节，差值才有意义。
    bool digest_disk(std::size_t index, std::uint8_t out[32]) noexcept {
        if (!loaded() || index >= section_count_ || out == nullptr)
            return false;

        const SectionView& section = sections_[index];
        const std::size_t size = comparable_size(section);
        if (size == 0 || size > MAX_SECTION_BYTES)
            return false;

        LARGE_INTEGER offset{};
        offset.QuadPart = section.raw_offset;
        if (!SetFilePointerEx(file_, offset, nullptr, FILE_BEGIN))
            return false;

        std::uint8_t buffer[CHUNK];
        Sha256 ctx;
        ctx.init();

        std::size_t remaining = size;
        while (remaining > 0) {
            const DWORD want = static_cast<DWORD>(
                remaining < CHUNK ? remaining : CHUNK);
            DWORD read = 0;
            if (!ReadFile(file_, buffer, want, &read, nullptr) || read == 0)
                return false;
            ctx.update(buffer, read);
            remaining -= read;
        }

        ctx.final(out);
        veil::detail::secure_wipe(buffer, sizeof(buffer));
        return true;
    }

    // 内存侧摘要，覆盖与磁盘侧完全相同的字节范围。
    bool digest_memory(std::size_t index, std::uint8_t out[32]) const noexcept {
        if (image_base_ == nullptr || index >= section_count_ || out == nullptr)
            return false;

        const SectionView& section = sections_[index];
        const std::size_t size = comparable_size(section);
        if (size == 0)
            return false;

        const auto* bytes = static_cast<const std::uint8_t*>(image_base_) +
                            section.virtual_address;
        Sha256::hash(bytes, size, out);
        return true;
    }

private:
    static std::size_t comparable_size(const SectionView& section) noexcept {
        const std::size_t raw = section.raw_size;
        const std::size_t virt = section.virtual_size;
        if (raw == 0 || virt == 0)
            return 0;
        return raw < virt ? raw : virt;
    }

    static constexpr std::size_t MAX_SECTIONS = 96;
    static constexpr std::size_t MAX_SECTION_BYTES = 64u * 1024u * 1024u;
    static constexpr std::size_t CHUNK = 16u * 1024u;

    HANDLE file_ = INVALID_HANDLE_VALUE;
    void* image_base_ = nullptr;
    std::size_t section_count_ = 0;
    SectionView sections_[MAX_SECTIONS]{};
};

}  // namespace veil::platform
