cmake_minimum_required(VERSION 3.16)

project(DpdkTutorials)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++23 -msse4")
set(CMAKE_BUILD_TYPE Debug)

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
