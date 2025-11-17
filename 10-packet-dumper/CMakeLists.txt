set(TARGET_NAME "packet-dumper")

find_package(Protobuf REQUIRED)

add_executable(${TARGET_NAME}
  main.cpp
  common.hpp
  packet_dumper.hpp
)

include(../dpdk-tutorials.cmake)

target_compile_definitions(${TARGET_NAME} PRIVATE
  RTE_SDK=/usr/local/
  RTE_TARGET=x86_64-default-linuxapp-gcc
)

target_link_libraries(${TARGET_NAME} PUBLIC
  pcap
  -lrte_eal
  -lrte_ethdev
  -lrte_mempool
  -lrte_mbuf
  -lrte_ring
)
