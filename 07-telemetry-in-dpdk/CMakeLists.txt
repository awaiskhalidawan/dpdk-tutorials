set(TARGET_NAME "telemetry-in-dpdk")

add_executable(${TARGET_NAME}
  main.cpp
)

include(../dpdk-tutorials.cmake)

