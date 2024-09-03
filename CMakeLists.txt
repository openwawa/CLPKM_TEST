cmake_minimum_required (VERSION 3.16)
set(CMAKE_CXX_STANDARD 11)

project ("CLPKM_TEST")
set(target ${CMAKE_PROJECT_NAME})


#开启优化加速
# 设置 Release 模式下的 C 和 C++ 编译器标志
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -msse4.1 -mpclmul -march=native -funroll-loops")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -msse4.1 -mssse3 -march=native -funroll-loops")

# 设置 Debug 模式下的 C 和 C++ 编译器标志
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
set(CMAKE_BUILD_TYPE Release)
# 将源代码添加到此项目的可执行文件。
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/gmssl)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/CLPKM)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test)



file(GLOB ALL_SOURCES 
    CLPKM/*.cpp
	gmssl/*.c
	test/*.cpp
	include/*/*.h
)
add_executable (${target} "main.cpp" "main.h"  ${ALL_SOURCES})


#socket lib
if (WIN32)
	target_link_libraries(${target} PRIVATE -lws2_32)
elseif (APPLE)
	target_link_libraries(${target} PRIVATE dl)
	target_link_libraries(${target} PRIVATE "-framework Security")
	#target_link_libraries(SM2_DCU_ACCE "-framework CoreFoundation") # rand_apple.c CFRelease()
elseif (MINGW)
	target_link_libraries(${target}  PRIVATE wsock32)
else()
	target_link_libraries(${target} PRIVATE dl)
	target_link_libraries(${target} PRIVATE pthread)

endif()

