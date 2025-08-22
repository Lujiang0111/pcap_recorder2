cmake_minimum_required(VERSION 3.10)

project(pcap_recorder2 VERSION 1.0)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 构建类型默认为Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# 源文件
file(GLOB_RECURSE srcs "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

# 创建可执行文件
add_executable(${PROJECT_NAME} ${srcs})

# 设置输出目录
set(bin_dir ${CMAKE_CURRENT_BINARY_DIR}/bin)
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${bin_dir})
set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${bin_dir})

# 获取系统和架构类型
set(os_name "debian")
set(os_version "12")
set(os_arch "${CMAKE_SYSTEM_PROCESSOR}")

if(WIN32)
    set(os_name "windows")
    set(os_version "msvc")
    set(os_arch "x86_64")
else()
    if(EXISTS "/etc/os-release")
        file(READ "/etc/os-release" os_release_content)
        string(REGEX REPLACE "\n" ";" os_release_lines "${os_release_content}")
        foreach(line IN LISTS os_release_lines)
            if(line MATCHES "^ID=\"?([^\"]+)\"?")
                set(os_name "${CMAKE_MATCH_1}")
            elseif(line MATCHES "^VERSION_ID=\"?([^\"]+)\"?")
                set(os_version "${CMAKE_MATCH_1}")
            endif()
        endforeach()
    endif()
endif()

message(STATUS "os name=${os_name}, os version=${os_version}, os arch=${os_arch}, build type=${CMAKE_BUILD_TYPE}")

# 指定目标的包含目录
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/dep/include/lccl
    ${CMAKE_CURRENT_BINARY_DIR}/dep/include/pcap_dump
)

# 链接库目录
target_link_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/dep/lib)

# 链接库
target_link_libraries(${PROJECT_NAME} PRIVATE lccl)
target_link_libraries(${PROJECT_NAME} PRIVATE pcap_dump)

set(prebuild_lib_base_path "${CMAKE_CURRENT_SOURCE_DIR}/../../../version/lib")
set(prebuild_libs "lccl 1.0 \
    pcap_dump 1.0")

set(postbuild_lib_base_path "${CMAKE_CURRENT_SOURCE_DIR}/../../../version/lib")
set(postbuild_libs "lccl 1.0 \
    pcap_dump 1.0")

# 系统自定义参数
if(os_name MATCHES "windows")
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8) # 兼容fmt库
    target_compile_options(${PROJECT_NAME} PRIVATE /MP)

    # 屏蔽特定告警
    target_compile_options(${PROJECT_NAME} PRIVATE /wd4996)

    # 添加特定库
    set(postbuild_libs
        "${postbuild_libs} \
        zlib 1.3.1"
    )
else()
endif()

# 编译前操作
add_custom_target(
    ${PROJECT_NAME}_prebuild
    COMMAND ${CMAKE_COMMAND} -E env python3 ${CMAKE_CURRENT_SOURCE_DIR}/prebuild.py ${os_name} ${os_version} ${os_arch} ${CMAKE_BUILD_TYPE} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${prebuild_lib_base_path} ${prebuild_libs}
)

add_dependencies(${PROJECT_NAME} ${PROJECT_NAME}_prebuild)

# 编译后操作
add_custom_command(
    TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E env python3 ${CMAKE_CURRENT_SOURCE_DIR}/postbuild.py ${os_name} ${os_version} ${os_arch} ${CMAKE_BUILD_TYPE} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${postbuild_lib_base_path} ${postbuild_libs}
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/conf ${bin_dir}
)
