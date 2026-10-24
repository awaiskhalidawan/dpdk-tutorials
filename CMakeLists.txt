cmake_minimum_required(VERSION 3.16)

project(DpdkTutorials)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

message("DPDK library version: ${DPDK_VERSION}")

if(NOT DPDK_VERSION VERSION_EQUAL "25.11.4")
  message(FATAL_ERROR "DPDK version 25.11.4 is required. Currently installed version is: ${DPDK_VERSION}")
endif()

message("DPDK include directory path: ${DPDK_INCLUDE_DIRS}")

set(ALLOWED_BUILD_TYPES Debug Release RelWithDebInfo MinSizeRel)
if(NOT CMAKE_BUILD_TYPE IN_LIST ALLOWED_BUILD_TYPES)
  message(FATAL_ERROR
    "Invalid CMAKE_BUILD_TYPE: '${CMAKE_BUILD_TYPE}'. "
    "Must be one of: ${ALLOWED_BUILD_TYPES}")
endif()

message("Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++23 -msse4")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_subdirectory(01-reading-a-packet-from-nic)
add_subdirectory(02-sending-a-packet-from-nic)
add_subdirectory(03-processing-a-packet)
add_subdirectory(04-getting-nic-statistics)
add_subdirectory(05-ipv4-checksum-calculation-offloading-to-nic)
add_subdirectory(06-receive-side-scaling)
add_subdirectory(07-telemetry-in-dpdk)
add_subdirectory(08-multiprocess-communication)
add_subdirectory(09-packet-generator)
add_subdirectory(10-packet-dumper)
add_subdirectory(11-rss-toeplitz-hash-test)
add_subdirectory(12-packet-classification-and-access-control)
add_subdirectory(13-packet-types-check)
add_subdirectory(14-ipsec-outbound)
add_subdirectory(15-rte-flow)
add_subdirectory(16-deep-packet-inspection)
