set(TARGET_NAME "packet-types-check")

add_executable(${TARGET_NAME}
  main.cpp
)

include(../dpdk-tutorials.cmake)

