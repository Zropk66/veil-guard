#include <veil/platform/image_map.hpp>
#include "support/test_main.hpp"

#include <cstring>

int main() {
    using namespace veil;
    using namespace veil::platform;

    const void* self = GetModuleHandleA(nullptr);
    test::expect(self != nullptr, "resolves the running module");

    // 映像描述
    {
        ImageLayout layout{};
        test::expect(describe_image(self, &layout), "describes the running image");
        test::expect(layout.base == self, "layout reports the image base");
        test::expect(layout.size_of_image > 0, "image size is nonzero");
        test::expect(layout.exception_table.VirtualAddress != 0,
                     "image carries an exception table");
        test::expect(layout.exception_table.Size > 0, "exception table is nonempty");

        test::expect(!describe_image(nullptr, &layout),
                     "null module is rejected");
        test::expect(!describe_image(self, nullptr),
                     "null output is rejected");

        // 非 PE 数据必须拒绝
        const char garbage[] = "not a portable executable";
        test::expect(!describe_image(garbage, &layout),
                     "non PE data is rejected");
    }

    // 段表
    {
        const IMAGE_SECTION_HEADER* sections = section_table(self);
        test::expect(sections != nullptr, "resolves the section table");

        const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(self);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const std::uint8_t*>(self) + dos->e_lfanew);
        const std::size_t count = nt->FileHeader.NumberOfSections;
        test::expect(count > 0, "image declares at least one section");

        bool found_text = false;
        bool found_reloc = false;
        for (std::size_t i = 0; i < count; ++i) {
            const char* name = reinterpret_cast<const char*>(sections[i].Name);
            if (std::strncmp(name, ".text", 5) == 0)
                found_text = true;
            if (std::strncmp(name, ".reloc", 6) == 0)
                found_reloc = true;
        }
        test::expect(found_text, "section table contains code");
        test::expect(found_reloc, "section table contains relocations");
    }

    // 重定位遍历
    {
        ImageLayout layout{};
        describe_image(self, &layout);
        test::expect(layout.relocations.VirtualAddress != 0,
                     "running image carries a relocation table");

        RelocationWalker walker;
        test::expect(walker.init(layout), "initialises the relocation walker");
        walker.bind_base(layout);

        std::size_t visited = 0;
        std::size_t dir64 = 0;
        std::size_t absolute = 0;
        std::size_t outside = 0;

        const auto begin = reinterpret_cast<std::uintptr_t>(layout.base);
        const auto end = begin + layout.size_of_image;

        void* target = nullptr;
        std::uint32_t type = 0;
        while (walker.next(&target, &type)) {
            ++visited;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                ++absolute;
                test::expect(target == nullptr,
                             "absolute entries carry no target");
                continue;
            }

            if (type == IMAGE_REL_BASED_DIR64)
                ++dir64;

            if (target == nullptr)
                continue;

            const auto address = reinterpret_cast<std::uintptr_t>(target);
            if (address < begin || address >= end)
                ++outside;
        }

        test::expect(visited > 0, "walker visits relocation entries");
        test::expect(dir64 > 0, "image contains 64 bit relocations");
        test::expect(outside == 0, "every target lies inside the image");
        test::expect(absolute <= visited,
                     "alignment padding never exceeds the entry count");

        // 重复遍历必须一致
        RelocationWalker again;
        again.init(layout);
        again.bind_base(layout);
        std::size_t second_visit = 0;
        while (again.next(&target, &type))
            ++second_visit;
        test::expect(second_visit == visited,
                     "relocation traversal is repeatable");
    }

    // 无重定位表时必须拒绝而不是返回垃圾项
    {
        ImageLayout layout{};
        layout.base = static_cast<const std::uint8_t*>(self);
        layout.relocations.VirtualAddress = 0;
        layout.relocations.Size = 0;

        RelocationWalker walker;
        test::expect(!walker.init(layout),
                     "walker rejects an image without relocations");

        void* target = nullptr;
        std::uint32_t type = 0;
        test::expect(!walker.next(&target, &type),
                     "uninitialised walker yields nothing");
    }

    return test::finish("image_map");
}
