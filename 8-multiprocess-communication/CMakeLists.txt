set(PRI_TARGET_NAME "primary-dpdk-process")
set(SEC_TARGET_NAME "secondary-dpdk-process")

add_executable(${PRI_TARGET_NAME}
  primary_process.cpp
)

add_executable(${SEC_TARGET_NAME}
  secondary_process.cpp
)

target_compile_definitions(${PRI_TARGET_NAME} PRIVATE
  RTE_SDK=/usr/local/
  RTE_TARGET=x86_64-default-linuxapp-gcc
)

target_compile_definitions(${PRI_TARGET_NAME} PRIVATE
  RTE_SDK=/usr/local/
  RTE_TARGET=x86_64-default-linuxapp-gcc
)

target_link_libraries(${PRI_TARGET_NAME} PUBLIC
  -lrte_eal
  -lrte_ethdev
  -lrte_mempool
  -lrte_mbuf
  -lrte_ring
)

target_compile_definitions(${SEC_TARGET_NAME} PRIVATE
  RTE_SDK=/usr/local/
  RTE_TARGET=x86_64-default-linuxapp-gcc
)

target_compile_definitions(${SEC_TARGET_NAME} PRIVATE
  RTE_SDK=/usr/local/
  RTE_TARGET=x86_64-default-linuxapp-gcc
)

target_link_libraries(${SEC_TARGET_NAME} PUBLIC
  -lrte_eal
  -lrte_ethdev
  -lrte_mempool
  -lrte_mbuf
  -lrte_ring
)

install(TARGETS ${PRI_TARGET_NAME}
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(TARGETS ${SEC_TARGET_NAME}
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)