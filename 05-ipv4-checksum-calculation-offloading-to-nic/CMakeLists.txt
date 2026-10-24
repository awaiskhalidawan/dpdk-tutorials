set(TARGET_NAME "ipv4-checksum-calculation-offloading-to-nic")

add_executable(${TARGET_NAME}
  main.cpp
)

include(../dpdk-tutorials.cmake)

