set(TARGET_NAME "packet-processor")

find_package(Protobuf REQUIRED)

add_executable(${TARGET_NAME}
  rule_manager.cpp
  main.cpp
  rule_management_grpc_server/rule_messages.grpc.pb.cc
  rule_management_grpc_server/rule_messages.pb.cc
  rule_management_grpc_server/rule_management_server.cpp
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
  -lrte_acl
  -lgrpc++ 
  protobuf::libprotobuf
)
