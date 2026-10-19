#pragma once

#include "../config.hpp"
#include "../detail/common.hpp"

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace veil::platform {

// PE 映像解析。
//
// 重映射需要三样东西：段的原始字节与虚拟地址、基址重定位表、
// 以及 .pdata 展开信息。三者都从映像头派生，不依赖任何导出符号。
struct ImageLayout {
    const std::uint8_t* base;
    std::uint32_t size_of_image;
    IMAGE_DATA_DIRECTORY relocations;
    IMAGE_DATA_DIRECTORY exception_table;
};

inline bool describe_image(const void* module, ImageLayout* out) noexcept {
    if (module == nullptr || out == nullptr)
        return false;

    const auto* base = static_cast<const std::uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + static_cast<std::ptrdiff_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    out->base = base;
    out->size_of_image = nt->OptionalHeader.SizeOfImage;
    out->relocations =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    out->exception_table =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    return true;
}

inline const IMAGE_SECTION_HEADER* section_table(const void* module) noexcept {
    if (module == nullptr)
        return nullptr;

    const auto* base = static_cast<const std::uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + static_cast<std::ptrdiff_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    return IMAGE_FIRST_SECTION(nt);
}

// 基址重定位表遍历。
//
// 表由变长块组成，每块以 IMAGE_BASE_RELOCATION 开头，紧跟一组
// 16 位项，块长度为 0 即结束。项的高四位是类型，低十二位是页内偏移。
//
// x64 映像主要使用 DIR64，IMAGE_REL_BASED_HIGHLOW 与
// IMAGE_REL_BASED_ABSOLUTE 也会出现：前者需按 32 位修正，
// 后者是对齐填充必须跳过。
class RelocationWalker {
public:
    bool init(const ImageLayout& layout) noexcept {
        if (layout.relocations.VirtualAddress == 0 ||
            layout.relocations.Size < sizeof(IMAGE_BASE_RELOCATION))
            return false;

        table_ = layout.base + layout.relocations.VirtualAddress;
        table_size_ = layout.relocations.Size;
        cursor_ = 0;
        block_ = nullptr;
        items_ = nullptr;
        item_index_ = 0;
        item_count_ = 0;
        return true;
    }

    // 返回一项。type 为 0 表示对齐填充，target 同时为空。
    bool next(void** target, std::uint32_t* type) noexcept {
        if (table_ == nullptr)
            return false;

        if (item_index_ >= item_count_ && !advance_block())
            return false;

        const std::uint16_t item = items_[item_index_++];
        const std::uint32_t kind = item >> 12;
        const std::uint32_t offset = item & 0x0FFFu;

        if (type != nullptr)
            *type = kind;

        if (kind == IMAGE_REL_BASED_ABSOLUTE) {
            if (target != nullptr)
                *target = nullptr;
            return true;
        }

        if (target != nullptr)
            *target = const_cast<std::uint8_t*>(table_) - table_offset_ +
                      block_->VirtualAddress + offset;
        return true;
    }

private:
    bool advance_block() noexcept {
        while (cursor_ + sizeof(IMAGE_BASE_RELOCATION) <= table_size_) {
            const auto* candidate = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                table_ + cursor_);
            if (candidate->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
                return false;

            const std::uint32_t entries =
                (candidate->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                sizeof(std::uint16_t);

            if (cursor_ + candidate->SizeOfBlock > table_size_)
                return false;

            block_ = candidate;
            items_ = reinterpret_cast<const std::uint16_t*>(
                table_ + cursor_ + sizeof(IMAGE_BASE_RELOCATION));
            item_index_ = 0;
            item_count_ = entries;

            cursor_ += candidate->SizeOfBlock;

            if (entries > 0)
                return true;
        }
        return false;
    }

    const std::uint8_t* table_ = nullptr;
    std::uint32_t table_size_ = 0;
    std::uint32_t cursor_ = 0;
    const IMAGE_BASE_RELOCATION* block_ = nullptr;
    const std::uint16_t* items_ = nullptr;
    std::uint32_t item_index_ = 0;
    std::uint32_t item_count_ = 0;
    // 表的起始偏移，用于把表内偏移换算回映像基址
    std::ptrdiff_t table_offset_ = 0;

public:
    void bind_base(const ImageLayout& layout) noexcept {
        table_offset_ = table_ - layout.base;
    }
};

}  // namespace veil::platform
