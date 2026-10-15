cmake_minimum_required(VERSION 3.20)
project(MocikaNativeVmpFixture LANGUAGES CXX)

if(NOT MOCIKA_NATIVE_VMP_PLUGIN)
    message(FATAL_ERROR "MOCIKA_NATIVE_VMP_PLUGIN is required")
endif()
if(NOT MOCIKA_NATIVE_VMP_OPT)
    message(FATAL_ERROR "MOCIKA_NATIVE_VMP_OPT is required")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/MocikaNativeVmp.cmake")
# 覆盖只启用 CXX 的接入；纯 C 路径由 check-build.py 和 Android 样本检查。
add_executable(mocika-native-vmp-fixture "$<$<CONFIG:Release>:main.c>")
set_source_files_properties(main.c PROPERTIES LANGUAGE CXX)
mocika_enable_native_vmp(mocika-native-vmp-fixture
    PLUGIN "${MOCIKA_NATIVE_VMP_PLUGIN}"
    LLVM_OPT "${MOCIKA_NATIVE_VMP_OPT}")
