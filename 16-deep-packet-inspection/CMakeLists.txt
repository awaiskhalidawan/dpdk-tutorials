set(TARGET_NAME "deep-packet-inspection")

find_package(PkgConfig REQUIRED)
pkg_check_modules(NDPI REQUIRED libndpi)

add_executable(${TARGET_NAME}
  main.cpp
  ndpi_util.hpp
  flow_table.hpp
)

include(../dpdk-tutorials.cmake)

target_include_directories(${TARGET_NAME} PRIVATE ${NDPI_INCLUDE_DIRS})
target_compile_options(${TARGET_NAME} PRIVATE ${NDPI_CFLAGS_OTHER})

target_compile_definitions(${TARGET_NAME} PRIVATE
  RTE_SDK=/usr/local/
  RTE_TARGET=x86_64-default-linuxapp-gcc
)

target_link_libraries(${TARGET_NAME} PUBLIC
  ${NDPI_LIBRARIES}
  -lrte_eal
  -lrte_ethdev
  -lrte_mempool
  -lrte_mbuf
  -lrte_net
)
