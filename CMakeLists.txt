cmake_minimum_required(VERSION 3.16)

project(DpdkTutorials)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++23 -msse4")
set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_subdirectory(1-reading-a-packet-from-nic)
add_subdirectory(2-sending-a-packet-from-nic)
add_subdirectory(3-processing-a-packet)
add_subdirectory(4-getting-nic-statistics)
add_subdirectory(5-ipv4-checksum-calculation-offloading-to-nic)
add_subdirectory(6-receive-side-scaling)
add_subdirectory(7-telemetry-in-dpdk)
add_subdirectory(8-multiprocess-communication)
add_subdirectory(9-packet-generator)
add_subdirectory(11-rss-toeplitz-hash-test)
