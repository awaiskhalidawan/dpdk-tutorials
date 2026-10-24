set(TARGET_NAME "receive-side-scaling")

add_executable(${TARGET_NAME}
  main.cpp
)

include(../dpdk-tutorials.cmake)

