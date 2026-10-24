set(TARGET_NAME "packet-classification-and-access-control")

add_executable(${TARGET_NAME}
  main.cpp
)

include(../dpdk-tutorials.cmake)

