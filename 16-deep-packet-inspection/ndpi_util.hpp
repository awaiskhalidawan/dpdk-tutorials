// MIT License
//
// Copyright (c) 2026 Muhammad Awais Khalid

#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
}

namespace ndpi_util {

struct NdpiContext {
    ndpi_detection_module_struct *detection {nullptr};
};

inline int init(NdpiContext &ctx)
{
    ctx.detection = ndpi_init_detection_module(nullptr);
    if (!ctx.detection) {
        std::cerr << "Unable to initialize nDPI detection module" << std::endl;
        return -1;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(ctx.detection, &protos);

    if (ndpi_finalize_initialization(ctx.detection) != 0) {
        std::cerr << "Unable to finalize nDPI initialization" << std::endl;
        ndpi_exit_detection_module(ctx.detection);
        ctx.detection = nullptr;
        return -1;
    }

    std::cout << "nDPI detection module ready. Max protocol id: "
              << NDPI_MAX_SUPPORTED_PROTOCOLS << std::endl;
    return 0;
}

inline ndpi_flow_struct *alloc_flow()
{
    auto *flow = static_cast<ndpi_flow_struct *>(ndpi_flow_malloc(SIZEOF_FLOW_STRUCT));
    if (flow) {
        std::memset(flow, 0, SIZEOF_FLOW_STRUCT);
    }
    return flow;
}

inline void free_flow(ndpi_flow_struct *flow)
{
    if (flow) {
        ndpi_free_flow(flow);
    }
}

inline ndpi_protocol process_packet(NdpiContext &ctx,
                                    ndpi_flow_struct *flow,
                                    const uint8_t *l3,
                                    uint16_t l3_len,
                                    uint64_t time_ms)
{
    return ndpi_detection_process_packet(ctx.detection, flow, l3, l3_len, time_ms, nullptr);
}

inline uint16_t preferred_protocol_id(const ndpi_protocol &proto)
{
    if (proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
        return proto.proto.app_protocol;
    }
    return proto.proto.master_protocol;
}

inline const char *protocol_name(NdpiContext &ctx, uint16_t proto_id)
{
    const char *name = ndpi_get_proto_name(ctx.detection, proto_id);
    return name ? name : "Unknown";
}

inline void cleanup(NdpiContext &ctx)
{
    if (ctx.detection) {
        ndpi_exit_detection_module(ctx.detection);
        ctx.detection = nullptr;
    }
}

} // namespace ndpi_util
