set(TARGET_NAME "rte-flow")

add_executable(${TARGET_NAME}
  main.cpp
  flow_util.hpp
)

include(../dpdk-tutorials.cmake)

