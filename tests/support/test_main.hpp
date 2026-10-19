#pragma once

#include <cstdio>

namespace veil::test {

inline int failures = 0;

inline void expect(bool condition, const char* label) {
    if (!condition) {
        std::printf("FAIL: %s\n", label);
        ++failures;
    } else {
        std::printf("ok: %s\n", label);
    }
    std::fflush(stdout);
}

inline int finish(const char* suite) {
    if (failures == 0) {
        std::printf("\nall %s tests passed\n", suite);
        return 0;
    }
    std::printf("\n%d %s test(s) failed\n", failures, suite);
    return 1;
}

}  // namespace veil::test
