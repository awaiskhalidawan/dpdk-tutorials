set(TARGET_NAME "reading-a-packet-from-nic")

add_executable(${TARGET_NAME}
    main.cpp
)

include(../dpdk-tutorials.cmake)

