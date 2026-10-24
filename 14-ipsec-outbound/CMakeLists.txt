set(TARGET_NAME "ipsec-outbound")

add_executable(${TARGET_NAME}
  main.cpp
  ipsec_util.hpp
  packet_dumper.hpp
)

include(../dpdk-tutorials.cmake)

target_link_libraries(${TARGET_NAME} PUBLIC
  pcap
)
