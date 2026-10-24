set(TARGET_NAME "packet-dumper")

find_package(Protobuf REQUIRED)

add_executable(${TARGET_NAME}
  main.cpp
  common.hpp
  packet_dumper.hpp
)

include(../dpdk-tutorials.cmake)

target_link_libraries(${TARGET_NAME} PUBLIC
  pcap
)
