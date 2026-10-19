cmake_minimum_required(VERSION 3.21)
project(veil LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

if(NOT WIN32)
    message(FATAL_ERROR "veil supports Windows x64 only")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "veil supports x64 only")
endif()

set(VEIL_MONOCYPHER_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher)

add_library(veil_monocypher STATIC
    ${VEIL_MONOCYPHER_ROOT}/src/monocypher.c
    ${VEIL_MONOCYPHER_ROOT}/src/optional/monocypher-ed25519.c
)
target_include_directories(veil_monocypher PUBLIC
    ${VEIL_MONOCYPHER_ROOT}/src
    ${VEIL_MONOCYPHER_ROOT}/src/optional
)
if(MSVC)
    target_compile_options(veil_monocypher PRIVATE /W3)
else()
    target_compile_options(veil_monocypher PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# 构建种子。未显式注入时回落到编译时间戳，但会发出警告：
# 时间戳派生的常量在两次构建间可能重合，去重效果弱于显式注入。
if(NOT DEFINED VEIL_BUILD_SEED)
    string(TIMESTAMP VEIL_BUILD_SEED "%Y%m%d%H%M%S" UTC)
    message(WARNING
        "VEIL_BUILD_SEED not set; falling back to ${VEIL_BUILD_SEED}. "
        "Inject a per-release value with -DVEIL_BUILD_SEED=<integer> for stable deduplication.")
endif()

if(MSVC)
    enable_language(ASM_MASM)
    set(VEIL_SYSCALL_STUB src/syscall_stub_msvc.asm)
else()
    enable_language(ASM)
    set(VEIL_SYSCALL_STUB src/syscall_stub_mingw.S)
endif()

add_library(veil_syscall OBJECT ${VEIL_SYSCALL_STUB})
if(NOT MSVC)
    set_source_files_properties(${VEIL_SYSCALL_STUB} PROPERTIES LANGUAGE ASM)
endif()

option(VEIL_HEADER_ONLY "Deliver veil as a header-only interface target" ON)
option(VEIL_BUILD_STATIC "Build the optional PIMPL static library target" OFF)

add_library(veil_header_only INTERFACE)
add_library(veil::header_only ALIAS veil_header_only)
target_include_directories(veil_header_only INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
# 汇编单元以对象文件形式并入每个消费者，避免把 C++ 专用选项传给汇编器
target_sources(veil_header_only INTERFACE
    $<TARGET_OBJECTS:veil_syscall>
    ${CMAKE_CURRENT_SOURCE_DIR}/src/probe_pin.cpp)
target_compile_definitions(veil_header_only INTERFACE
    VEIL_BUILD_SEED=${VEIL_BUILD_SEED}
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    VEIL_HEADER_ONLY=1
)
target_link_libraries(veil_header_only INTERFACE veil_monocypher ws2_32 secur32 crypt32)
if(MSVC)
    # /utf-8 必需：源文件以 UTF-8 保存并含中文注释，缺省代码页会让
    # 编译器在解析注释后的代码时错位
    target_compile_options(veil_header_only INTERFACE
        /W4 /permissive- /Zc:__cplusplus /utf-8)
else()
    # RDRAND 由运行期检查决定是否可用，但指令本身需要目标特性才可编码
    target_compile_options(veil_header_only INTERFACE -Wall -Wextra -mrdrnd)
endif()

# 可选静态库形态。与 header-only 共用同一套源文件，区别只在于
# 重实现单元被编译进库而不是在消费方内联展开，因此消费方看不到
# 这些符号的实现体，也无法在自身翻译单元里改写它们。
if(VEIL_BUILD_STATIC)
    add_library(veil_static STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/probe_pin.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/guard_impl.cpp)
    add_library(veil::static ALIAS veil_static)
    target_include_directories(veil_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(veil_static PUBLIC
        VEIL_BUILD_SEED=${VEIL_BUILD_SEED}
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN)
    target_link_libraries(veil_static PUBLIC veil_monocypher ws2_32 secur32 crypt32)
    if(MSVC)
        target_compile_options(veil_static PUBLIC
            /W4 /permissive- /Zc:__cplusplus /utf-8)
    else()
        target_compile_options(veil_static PUBLIC -Wall -Wextra -mrdrnd)
    endif()
endif()

option(VEIL_BUILD_TESTS "Build veil tests" OFF)

set(VEIL_TEST_TARGETS
    sha256_test hmac_hkdf_test aes_test aes_gcm_test ed25519_test
    syscall_test peb_test image_file_test scan_test image_map_test remap_test
    anti_debug_test code_integrity_test module_topo_test
    layout_test binder_test zero_baseline_test envelope_test vectors_test
    guard_test tls_client_test tls_live_test spki_test)

if(VEIL_BUILD_TESTS)
    enable_testing()
    foreach(test_name IN LISTS VEIL_TEST_TARGETS)
        # 逐个交付期间允许源文件尚不存在，否则 CMake 在 generate 阶段
        # 直接终止，无法按任务增量构建。缺项在此登记，构建末尾统一校验。
        if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/${test_name}.cpp)
            message(STATUS "veil: test source tests/${test_name}.cpp not present yet")
            continue()
        endif()
        add_executable(${test_name} tests/${test_name}.cpp)
        target_link_libraries(${test_name} PRIVATE veil::header_only)
        # 夹具测试需要从仓库根读取跨实现向量
        add_test(NAME ${test_name} COMMAND ${test_name}
                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endforeach()
endif()

# 发版前必须确认全部测试源已就位，避免缺项被静默跳过。
option(VEIL_REQUIRE_ALL_TESTS "Fail configuration when a test source is missing" OFF)
if(VEIL_BUILD_TESTS AND VEIL_REQUIRE_ALL_TESTS)
    foreach(test_name IN LISTS VEIL_TEST_TARGETS)
        if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/${test_name}.cpp)
            message(FATAL_ERROR "missing test source tests/${test_name}.cpp")
        endif()
    endforeach()
endif()
