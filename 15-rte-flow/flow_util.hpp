// MIT License
//
// Copyright (c) 2026 Muhammad Awais Khalid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <iostream>
#include <cstring>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_byteorder.h>

// Print basic flow engine information for the selected port.
// Different NICs / PMDs support different match items and actions. Always
// validate a rule (rte_flow_validate) before creating it.
inline void print_flow_info(const uint16_t port_id)
{
    struct rte_flow_port_info port_info {};
    struct rte_flow_queue_info queue_info {};
    struct rte_flow_error error {};

    const int ret = rte_flow_info_get(port_id, &port_info, &queue_info, &error);
    if (ret != 0) {
        std::cerr << "Unable to get flow info for port Id: " << port_id
                  << " Return code: " << ret
                  << " Error type: " << error.type
                  << " Message: " << (error.message ? error.message : "n/a")
                  << std::endl;
        return;
    }

    std::cout << "Flow engine info (port Id: " << port_id << ")" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << " Max queues: " << port_info.max_nb_queues << std::endl;
    std::cout << " Max counters: " << port_info.max_nb_counters << std::endl;
    std::cout << " Max aging objects: " << port_info.max_nb_aging_objects << std::endl;
    std::cout << " Max meters: " << port_info.max_nb_meters << std::endl;
    std::cout << " Max conntrack objects: " << port_info.max_nb_conn_tracks << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
}

// Build an IPv4/UDP destination-port match pattern.
// Pattern chain: ETH -> IPV4 -> UDP -> END
// Empty ETH/IPV4 specs with zero masks match any Ethernet/IPv4 header.
// Only the UDP destination port is constrained.
inline void build_ipv4_udp_dport_pattern(const uint16_t udp_dport,
                                         struct rte_flow_item_eth &eth_spec,
                                         struct rte_flow_item_eth &eth_mask,
                                         struct rte_flow_item_ipv4 &ipv4_spec,
                                         struct rte_flow_item_ipv4 &ipv4_mask,
                                         struct rte_flow_item_udp &udp_spec,
                                         struct rte_flow_item_udp &udp_mask,
                                         struct rte_flow_item pattern[4])
{
    std::memset(&eth_spec, 0, sizeof(eth_spec));
    std::memset(&eth_mask, 0, sizeof(eth_mask));
    std::memset(&ipv4_spec, 0, sizeof(ipv4_spec));
    std::memset(&ipv4_mask, 0, sizeof(ipv4_mask));
    std::memset(&udp_spec, 0, sizeof(udp_spec));
    std::memset(&udp_mask, 0, sizeof(udp_mask));

    udp_spec.hdr.dst_port = rte_cpu_to_be_16(udp_dport);
    udp_mask.hdr.dst_port = 0xffff;

    pattern[0] = {
        .type = RTE_FLOW_ITEM_TYPE_ETH,
        .spec = &eth_spec,
        .last = nullptr,
        .mask = &eth_mask,
    };
    pattern[1] = {
        .type = RTE_FLOW_ITEM_TYPE_IPV4,
        .spec = &ipv4_spec,
        .last = nullptr,
        .mask = &ipv4_mask,
    };
    pattern[2] = {
        .type = RTE_FLOW_ITEM_TYPE_UDP,
        .spec = &udp_spec,
        .last = nullptr,
        .mask = &udp_mask,
    };
    pattern[3] = {
        .type = RTE_FLOW_ITEM_TYPE_END,
        .spec = nullptr,
        .last = nullptr,
        .mask = nullptr,
    };
}

// Validate then create a flow rule. Returns nullptr on failure and prints the
// driver error message so the reader can see which item/action is unsupported.
inline struct rte_flow *validate_and_create_flow(const uint16_t port_id,
                                                 const struct rte_flow_attr *attr,
                                                 const struct rte_flow_item pattern[],
                                                 const struct rte_flow_action actions[],
                                                 const char *rule_name)
{
    struct rte_flow_error error {};

    // Always validate before create. Validation checks whether the NIC/PMD
    // supports this pattern + action combination without programming hardware.
    int ret = rte_flow_validate(port_id, attr, pattern, actions, &error);
    if (ret != 0) {
        std::cerr << "Flow validate failed for rule '" << rule_name
                  << "'. Port Id: " << port_id
                  << " Return code: " << ret
                  << " Error type: " << error.type
                  << " Message: " << (error.message ? error.message : "n/a")
                  << std::endl;
        return nullptr;
    }

    std::cout << "Flow validate succeeded for rule '" << rule_name << "'." << std::endl;

    struct rte_flow *flow = rte_flow_create(port_id, attr, pattern, actions, &error);
    if (flow == nullptr) {
        std::cerr << "Flow create failed for rule '" << rule_name
                  << "'. Port Id: " << port_id
                  << " Error type: " << error.type
                  << " Message: " << (error.message ? error.message : "n/a")
                  << std::endl;
        return nullptr;
    }

    std::cout << "Flow create succeeded for rule '" << rule_name << "'." << std::endl;
    return flow;
}

// Create a rule that matches IPv4/UDP packets with the given destination port
// and redirects them to a specific RX queue (hardware steering).
inline struct rte_flow *create_queue_redirect_rule(const uint16_t port_id,
                                                   const uint16_t udp_dport,
                                                   const uint16_t target_queue)
{
    struct rte_flow_attr attr {};
    attr.ingress = 1;
    attr.priority = 0;

    struct rte_flow_item_eth eth_spec {};
    struct rte_flow_item_eth eth_mask {};
    struct rte_flow_item_ipv4 ipv4_spec {};
    struct rte_flow_item_ipv4 ipv4_mask {};
    struct rte_flow_item_udp udp_spec {};
    struct rte_flow_item_udp udp_mask {};
    struct rte_flow_item pattern[4];

    build_ipv4_udp_dport_pattern(udp_dport, eth_spec, eth_mask, ipv4_spec, ipv4_mask,
                                 udp_spec, udp_mask, pattern);

    struct rte_flow_action_queue queue_action {};
    queue_action.index = target_queue;

    struct rte_flow_action actions[2] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_QUEUE,
            .conf = &queue_action,
        },
        {
            .type = RTE_FLOW_ACTION_TYPE_END,
            .conf = nullptr,
        },
    };

    std::cout << "Installing QUEUE redirect rule: IPv4/UDP dport "
              << udp_dport << " -> RX queue " << target_queue << std::endl;

    return validate_and_create_flow(port_id, &attr, pattern, actions, "queue-redirect");
}

// Create a rule that matches IPv4/UDP packets with the given destination port
// and drops them in hardware (packets never reach the CPU RX path).
inline struct rte_flow *create_drop_rule(const uint16_t port_id, const uint16_t udp_dport)
{
    struct rte_flow_attr attr {};
    attr.ingress = 1;
    attr.priority = 0;

    struct rte_flow_item_eth eth_spec {};
    struct rte_flow_item_eth eth_mask {};
    struct rte_flow_item_ipv4 ipv4_spec {};
    struct rte_flow_item_ipv4 ipv4_mask {};
    struct rte_flow_item_udp udp_spec {};
    struct rte_flow_item_udp udp_mask {};
    struct rte_flow_item pattern[4];

    build_ipv4_udp_dport_pattern(udp_dport, eth_spec, eth_mask, ipv4_spec, ipv4_mask,
                                 udp_spec, udp_mask, pattern);

    struct rte_flow_action actions[2] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_DROP,
            .conf = nullptr,
        },
        {
            .type = RTE_FLOW_ACTION_TYPE_END,
            .conf = nullptr,
        },
    };

    std::cout << "Installing DROP rule: IPv4/UDP dport " << udp_dport << std::endl;

    return validate_and_create_flow(port_id, &attr, pattern, actions, "drop");
}

inline void destroy_flow_rule(const uint16_t port_id, struct rte_flow *flow, const char *rule_name)
{
    if (flow == nullptr) {
        return;
    }

    struct rte_flow_error error {};
    const int ret = rte_flow_destroy(port_id, flow, &error);
    if (ret != 0) {
        std::cerr << "Unable to destroy flow rule '" << rule_name
                  << "'. Port Id: " << port_id
                  << " Return code: " << ret
                  << " Error type: " << error.type
                  << " Message: " << (error.message ? error.message : "n/a")
                  << std::endl;
        return;
    }

    std::cout << "Destroyed flow rule '" << rule_name << "'." << std::endl;
}
