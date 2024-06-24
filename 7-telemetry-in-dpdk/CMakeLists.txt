set(TARGET_NAME "telemetry-in-dpdk")

add_executable(${TARGET_NAME}
  main.cpp
)

include(../dpdk-tutorials.cmake)

target_compile_definitions(${TARGET_NAME} PRIVATE
  RTE_SDK=/usr/local/
  RTE_TARGET=x86_64-default-linuxapp-gcc
)

target_link_libraries(${TARGET_NAME} PUBLIC
  -lrte_eal
  -lrte_ethdev
  -lrte_mempool
  -lrte_mbuf
  -lrte_telemetry
)