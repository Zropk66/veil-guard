#include <veil/platform/image_file.hpp>
#include "support/test_main.hpp"

#include <cstdio>
#include <cstring>

int main() {
    using namespace veil;
    using namespace veil::platform;

    ImageFile image;
    test::expect(image.open_self(), "opens the running module from disk");
    test::expect(image.loaded(), "reports loaded after open");
    test::expect(image.image_base() != nullptr, "exposes in-memory image base");

    const std::size_t count = image.section_count();
    test::expect(count > 0, "enumerates at least one section");
    SectionView scratch{};
    test::expect(!image.section_at(count, nullptr), "null section output is rejected");
    test::expect(!image.section_at(count, &scratch), "index past end is rejected");

    // 可执行段的磁盘字节必须与内存一致
    bool found_text = false;
    for (std::size_t i = 0; i < count; ++i) {
        SectionView section{};
        if (!image.section_at(i, &section))
            continue;
        if (!section.executable || section.raw_size == 0)
            continue;
        found_text = true;

        std::uint8_t disk_digest[32];
        std::uint8_t memory_digest[32];
        test::expect(image.digest_disk(i, disk_digest),
                     "digests executable section from disk");
        test::expect(image.digest_memory(i, memory_digest),
                     "digests executable section from memory");
        test::expect(detail::constant_time_compare(disk_digest, memory_digest, 32) == 1,
                     "executable section disk and memory digests agree");
        break;
    }
    test::expect(found_text, "finds at least one executable section");

    // 同一段重复摘要必须稳定
    if (found_text) {
        std::uint8_t again[32];
        std::uint8_t first[32];
        for (std::size_t i = 0; i < count; ++i) {
            SectionView section{};
            if (!image.section_at(i, &section))
                continue;
            if (!section.executable || section.raw_size == 0)
                continue;
            image.digest_disk(i, first);
            image.digest_disk(i, again);
            break;
        }
        test::expect(detail::constant_time_compare(first, again, 32) == 1,
                     "repeated disk digest is deterministic");
    }

    ImageFile missing;
    test::expect(!missing.loaded(), "unopened image reports unloaded");
    test::expect(missing.image_base() == nullptr,
                 "unopened image has no image base");
    std::uint8_t digest[32];
    test::expect(!missing.digest_disk(0, digest),
                 "unopened image cannot digest");
    test::expect(!missing.digest_memory(0, digest),
                 "unopened image cannot digest memory");
    test::expect(!missing.open_module(nullptr),
                 "null module base is rejected");
    test::expect(missing.section_count() == 0,
                 "failed open leaves no sections");

    return test::finish("image_file");
}
