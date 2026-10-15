include_guard(GLOBAL)

function(mocika_enable_native_vmp target)
    if(CMAKE_GENERATOR MATCHES "Makefiles")
        execute_process(COMMAND "${CMAKE_MAKE_PROGRAM}" --version OUTPUT_VARIABLE _make_version)
        if(_make_version MATCHES "GNU Make ([0-9]+)" AND CMAKE_MATCH_1 LESS 4)
            message(FATAL_ERROR "Native VMP 增量构建需要 Ninja 或 GNU Make 4+；旧 Make 无法可靠识别同秒内的工具更新")
        endif()
    endif()
    set(options)
    set(one_value_args PLUGIN LLVM_OPT)
    cmake_parse_arguments(MNV "${options}" "${one_value_args}" "" ${ARGN})

    if(NOT TARGET "${target}")
        message(FATAL_ERROR "mocika_enable_native_vmp: unknown target ${target}")
    endif()
    if(NOT MNV_PLUGIN OR NOT EXISTS "${MNV_PLUGIN}")
        message(FATAL_ERROR "mocika_enable_native_vmp: PLUGIN must name the built MocikaNativeVmpPass")
    endif()
    if(NOT MNV_LLVM_OPT OR NOT EXISTS "${MNV_LLVM_OPT}")
        message(FATAL_ERROR "mocika_enable_native_vmp: LLVM_OPT must name opt from the same LLVM build as the plugin")
    endif()
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" AND
       NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "Mocika Native VMP requires Clang/LLVM")
    endif()
    foreach(_language C CXX)
        get_target_property(_launcher "${target}" ${_language}_COMPILER_LAUNCHER)
        if(_launcher)
            message(FATAL_ERROR "Native VMP 目标不能叠加其他编译启动器；请先清除 ${_language}_COMPILER_LAUNCHER")
        endif()
    endforeach()
    get_target_property(_ipo "${target}" INTERPROCEDURAL_OPTIMIZATION)
    if(_ipo)
        message(FATAL_ERROR "Native VMP 暂不支持 LTO/IPO；不能让链接优化重新改写已核验函数")
    endif()

    get_filename_component(_mocika_vmp_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(_mocika_vmp_launcher
        "${Python3_EXECUTABLE};${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mocika_vmp_launcher.py;--opt;${MNV_LLVM_OPT};--plugin;${MNV_PLUGIN};--")
    set_property(TARGET "${target}" PROPERTY C_COMPILER_LAUNCHER
        "${_mocika_vmp_launcher}")
    set_property(TARGET "${target}" PROPERTY CXX_COMPILER_LAUNCHER
        "${_mocika_vmp_launcher}")
    target_sources("${target}" PRIVATE
        "${_mocika_vmp_root}/runtime/mocika_native_vmp.c")
    if(NOT CMAKE_C_COMPILER_LOADED)
        # 仅启用 CXX 的工程也必须编入运行时；实现兼容 C++，导出沿用头文件的 extern C。
        set_property(SOURCE "${_mocika_vmp_root}/runtime/mocika_native_vmp.c"
            TARGET_DIRECTORY "${target}" PROPERTY LANGUAGE CXX)
    endif()
    target_include_directories("${target}" PRIVATE
        "${_mocika_vmp_root}/include")
    target_compile_options("${target}" PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:-O2>")
    # 工具内容变化先重新配置，再用编译参数触发全部源文件重编译，包含条件或后追加的源。
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${MNV_PLUGIN}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mocika_vmp_launcher.py")
    file(SHA256 "${MNV_PLUGIN}" _plugin_sha256)
    file(SHA256 "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mocika_vmp_launcher.py" _launcher_sha256)
    target_compile_definitions("${target}" PRIVATE MOCIKA_NATIVE_VMP_ENABLED=1
        "MOCIKA_NATIVE_VMP_TOOLCHAIN=\"${_plugin_sha256}${_launcher_sha256}\"")
    if(UNIX AND NOT APPLE)
        # 直接追加私有链接项，兼容业务目标已有的 plain/keyword 两种 CMake 写法。
        set_property(TARGET "${target}" APPEND PROPERTY LINK_LIBRARIES m)
    endif()
    get_target_property(_target_type "${target}" TYPE)
    if((ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Linux") AND
       _target_type MATCHES "^(SHARED_LIBRARY|MODULE_LIBRARY|EXECUTABLE)$")
        get_filename_component(_llvm_bin "${MNV_LLVM_OPT}" DIRECTORY)
        set(_llvm_suffix "")
        if(CMAKE_HOST_WIN32)
            set(_llvm_suffix ".exe")
        endif()
        get_target_property(_source_dir "${target}" SOURCE_DIR)
        set(_sources_file "${CMAKE_CURRENT_BINARY_DIR}/${target}-$<CONFIG>.vmp-sources.txt")
        file(GENERATE OUTPUT "${_sources_file}" CONTENT "$<JOIN:$<TARGET_GENEX_EVAL:${target},$<TARGET_PROPERTY:${target},SOURCES>>,\n>")
        add_custom_command(TARGET "${target}" POST_BUILD
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mocika_vmp_evidence.py" seal
                --library "$<TARGET_FILE:${target}>" --output "$<TARGET_FILE:${target}>.native-vmp.json"
                --plugin "${MNV_PLUGIN}"
                --sources "${_sources_file}" --source-dir "${_source_dir}"
                --objects "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${target}.dir"
                --readobj "${_llvm_bin}/llvm-readobj${_llvm_suffix}"
                --objdump "${_llvm_bin}/llvm-objdump${_llvm_suffix}"
            VERBATIM)
        set_property(TARGET "${target}" APPEND PROPERTY LINK_DEPENDS
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mocika_vmp_evidence.py"
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mocika_vmp_launcher.py" "${MNV_PLUGIN}")
    endif()
endfunction()
