set(TARGET_NAME "sending-a-packet-from-nic")

add_executable(${TARGET_NAME}
  main.cpp
)

include(../dpdk-tutorials.cmake)

