// MIT License
//
// Copyright (c) 2025 Muhammad Awais Khalid
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

#include <iostream>
#include <expected>
#include <variant>
#include <cstring>
#include <string>
#include <list>
#include <vector>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_acl.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_udp.h>
#include <util.hpp>

constexpr uint8_t DEFAULT_MAX_CATEGORIES = 4;     // Default categories must be 1 or multiple of 4. It must also be less then equal to 16. 

static struct rte_acl_field_def ipv4_defs[5] = {
    /* first input field - always one byte long. */
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof (uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = offsetof(rte_ipv4_hdr, next_proto_id),
    },

    /* next input field (IPv4 source address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset = offsetof(rte_ipv4_hdr, src_addr),
    },

    /* next input field (IPv4 destination address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset = offsetof(rte_ipv4_hdr, dst_addr),
    },

    /*
     * Next 2 fields (src & dst ports) form 4 consecutive bytes.
     * They share the same input index.
     */
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset = offsetof(rte_ipv4_hdr, dst_addr) + sizeof(uint32_t),
    },

    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 4,
        .input_index = 3,
        .offset = offsetof(rte_ipv4_hdr, dst_addr) + sizeof(uint32_t) + sizeof(uint16_t),
    },
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));

static struct rte_acl_field_def ipv6_defs[11] = {
    /* first input field - always one byte long. */
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof (uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = offsetof(rte_ipv6_hdr, proto),
    },

    /* next input field (IPv6 source address) - 16 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset = offsetof(rte_ipv6_hdr, src_addr.a[0]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset = offsetof(rte_ipv6_hdr, src_addr.a[4]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 3,
        .input_index = 3,
        .offset = offsetof(rte_ipv6_hdr, src_addr.a[8]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 4,
        .input_index = 4,
        .offset = offsetof(rte_ipv6_hdr, src_addr.a[12]),
    },

    /* next input field (IPv6 destination address) - 16 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 5,
        .input_index = 5,
        .offset = offsetof(rte_ipv6_hdr, dst_addr.a[0]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 6,
        .input_index = 6,
        .offset = offsetof(rte_ipv6_hdr, dst_addr.a[4]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 7,
        .input_index = 7,
        .offset = offsetof(rte_ipv6_hdr, dst_addr.a[8]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 8,
        .input_index = 8,
        .offset = offsetof(rte_ipv6_hdr, dst_addr.a[12]),
    },
    /*
     * Next 2 fields (src & dst ports) form 4 consecutive bytes.
     * They share the same input index.
     */
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 9,
        .input_index = 9,
        .offset = offsetof(rte_ipv6_hdr, dst_addr.a[12]) + sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 10,
        .input_index = 9,
        .offset = offsetof(rte_ipv6_hdr, dst_addr.a[12]) + sizeof(uint32_t) + sizeof(uint16_t),
    },
};

RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

enum IP_VERSION : uint8_t {
    UNKNOWN = 0,
    IPV4,
    IPV6
};

std::expected<rte_mbuf *, std::string> create_packet(rte_mempool *const memory_pool,
                                                     const uint8_t protocol, 
                                                     const std::string& source_ip, 
                                                     const std::string& dest_ip,
                                                     const uint16_t source_port,
                                                     const uint16_t dest_port,
                                                     const IP_VERSION ip_version) {

    rte_mbuf *packet = nullptr;
    if (rte_mempool_get(memory_pool, reinterpret_cast<void **>(&packet)) != 0) {
        return std::unexpected("Error: Unable to get memory buffer from memory pool. ");
    }

    if (ip_version != IP_VERSION::IPV4 && ip_version != IP_VERSION::IPV6) {
        return std::unexpected("Error: Only IPv4/v6 is supported. ");
    }

    uint8_t *data = rte_pktmbuf_mtod(packet, uint8_t *);

    // Setting Ethernet header information (Source MAC, Destination MAC, Ethernet type).
    rte_ether_hdr *const eth_hdr = reinterpret_cast<rte_ether_hdr *>(data);

    uint8_t ip_header_size {0};
    if (ip_version == IP_VERSION::IPV4) {
        eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        ip_header_size = sizeof(rte_ipv4_hdr);
    } else if (ip_version == IP_VERSION::IPV6) {
        eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
        ip_header_size = sizeof(rte_ipv6_hdr);
    } else {
        return std::unexpected("Error: Unknown ip version detected. ");
    }

    const uint8_t src_mac_addr[6] = {0x08, 0x00, 0x27, 0x95, 0xBD, 0xAE};
    memcpy(eth_hdr->src_addr.addr_bytes, src_mac_addr, sizeof(src_mac_addr));

    const uint8_t dst_mac_addr[6] = {0x08, 0x00, 0x27, 0x35, 0x14, 0x15};
    memcpy(eth_hdr->dst_addr.addr_bytes, dst_mac_addr, sizeof(dst_mac_addr));

    
    if (ip_version == IP_VERSION::IPV4) {
        // Setting IPv4 header information.
        rte_ipv4_hdr *const ipv4_hdr = reinterpret_cast<rte_ipv4_hdr *>(data + sizeof(rte_ether_hdr));
        ipv4_hdr->version = 4;                          // Setting IP version as IPv4
        ipv4_hdr->ihl = 5;                              // Setting IP header length = 20 bytes = (5 * 4 Bytes)
        ipv4_hdr->type_of_service = 0;                  // Setting DSCP = 0; ECN = 0;
        ipv4_hdr->total_length = rte_cpu_to_be_16(200); // Setting total IPv4 packet length to 200 bytes. This includes the IPv4 header (20 bytes) as well.
        ipv4_hdr->packet_id = 0;                        // Setting identification = 0 as the packet is non-fragmented.
        ipv4_hdr->fragment_offset = 0x0040;             // Setting packet as non-fragmented and fragment offset = 0.
        ipv4_hdr->time_to_live = 64;                    // Setting Time to live = 64;
        ipv4_hdr->next_proto_id = protocol;             // Setting the next protocol.

        uint8_t src_ip_addr[4] = {0};
        if (inet_pton(AF_INET, source_ip.c_str(), src_ip_addr) != 1) {
            return std::unexpected("Unable to parse source ip address: " + source_ip);
        }
        memcpy(&ipv4_hdr->src_addr, src_ip_addr, sizeof(src_ip_addr)); // Setting source ip address.

        uint8_t dest_ip_addr[4] = {0};
        if (inet_pton(AF_INET, dest_ip.c_str(), dest_ip_addr) != 1) {
            return std::unexpected("Unable to parse dest ip address: " + dest_ip);
        }
        memcpy(&ipv4_hdr->dst_addr, dest_ip_addr, sizeof(dest_ip_addr)); // Setting destination ip address.

        ipv4_hdr->hdr_checksum = 0;
        ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr); // Calculating and setting IPv4 checksum in IPv4 header.
    } else if (ip_version == IP_VERSION::IPV6) {
        // Setting IPv6 header information.
        rte_ipv6_hdr *const ipv6_hdr = reinterpret_cast<rte_ipv6_hdr *>(data + sizeof(rte_ether_hdr));
        ipv6_hdr->version = 6;                             // Setting IP version as IPv6.
        ipv6_hdr->ds = 0;                                  // Setting DSCP = 0.
        ipv6_hdr->ecn = 0;                                 // Setting ECN = 0.
        ipv6_hdr->flow_label = 0;                          // Setting flow label = 0.
        ipv6_hdr->payload_len = rte_cpu_to_be_16(180);     // Setting payload length to 180 bytes. This excludes the IPv6 header (40 bytes).
        ipv6_hdr->hop_limits = 64;                         // Setting hop limit to 64.
        ipv6_hdr->proto = 17;                              // Setting the protocol.

        uint8_t src_ip_addr[16] = {0};
        if (inet_pton(AF_INET6, source_ip.c_str(), src_ip_addr) != 1) {
            return std::unexpected("Unable to parse source ip address: " + source_ip);
        }
        memcpy(&ipv6_hdr->src_addr.a, src_ip_addr, sizeof(src_ip_addr)); // Setting source ip address.

        uint8_t dest_ip_addr[16] = {0};
        if (inet_pton(AF_INET6, dest_ip.c_str(), dest_ip_addr) != 1) {
            return std::unexpected("Unable to parse dest ip address: " + dest_ip);
        }
        memcpy(&ipv6_hdr->dst_addr.a, dest_ip_addr, sizeof(dest_ip_addr)); // Setting destination ip address.
    } else {
        return std::unexpected("Error: Unknown ip version detected. ");
    }

    // Setting UDP header information.
    rte_udp_hdr *const udp_hdr = reinterpret_cast<rte_udp_hdr *>(data + sizeof(rte_ether_hdr) + ip_header_size);
    udp_hdr->dst_port = rte_cpu_to_be_16(dest_port);    // Setting destination port.
    udp_hdr->src_port = rte_cpu_to_be_16(source_port);  // Setting source port.
    udp_hdr->dgram_len = rte_cpu_to_be_16(180);         // Setting datagram length = 180;
    udp_hdr->dgram_cksum = 0;                           // Setting checksum = 0;

    // Setting data in the UDP payload.
    uint8_t *payload = data + sizeof(rte_ether_hdr) + ip_header_size + sizeof(rte_udp_hdr);
    memset(payload, 0, 172);
    const char sample_data[] = {"This is a sample packet generated by a DPDK application ..."};
    memcpy(payload, sample_data, sizeof(sample_data));

    return packet;
}

std::expected<std::variant<acl4_rule*, acl6_rule*, std::pair<acl4_rule*, acl6_rule*>>, bool> parse_rule(const std::string &rule_str) {
    static thread_local acl4_rule rule_ip4 = {0};
    static thread_local acl6_rule rule_ip6 = {0};

    int32_t rule_priority = 0;
    int8_t category = 0;
    uint8_t proto_low = 0, proto_high = 0;
    uint16_t src_port_low = 0, src_port_high = 0;
    uint16_t dst_port_low = 0, dst_port_high = 0;
    uint32_t src_ip4_mask = 0;
    uint32_t dst_ip4_mask = 0;
    uint32_t src_ip4 = 0;
    uint32_t dst_ip4 = 0;
    constexpr uint8_t IPV6_ADDRESS_SIZE = 16;
    uint32_t src_ip6[IPV6_ADDRESS_SIZE / 4] = {0};
    uint32_t dst_ip6[IPV6_ADDRESS_SIZE / 4] = {0};
    uint32_t src_ip6_mask[IPV6_ADDRESS_SIZE / 4] = {0};
    uint32_t dst_ip6_mask[IPV6_ADDRESS_SIZE / 4] = {0};

    bool is_priority_present = false;
    bool is_category_present = false;
    bool is_proto_present = false;
    bool is_src_port_present = false;
    bool is_dst_port_present = false;
    bool is_src_ip_present = false;
    bool is_dst_ip_present = false;
    bool is_ipv4_rule = false;
    bool is_ipv6_rule = false;

    const auto tokens = util::tokenize_string(rule_str, ' ');
    for (auto iter = tokens.begin(); iter != tokens.end();) {
        if (*iter == "pri") {
            if (++iter == tokens.end()) {
                std::cerr << "Invalid rule priority format. " << std::endl;
                return std::unexpected(false);
            }

            rule_priority = util::string_to_int(*iter);
            if (rule_priority < 0) {
                std::cerr << "Unable to parse rule priority. " << std::endl;
                return std::unexpected(false);
            }
            is_priority_present = true;
        } else if (*iter == "category") {
            if (++iter == tokens.end()) {
                std::cerr << "Invalid category format. " << std::endl;
                return std::unexpected(false);
            }

            category = util::string_to_int(*iter);
            if (category < 0) {
                std::cerr << "Unable to parse category. " << std::endl;
                return std::unexpected(false);
            }
            is_category_present = true;
        } else if (*iter == "proto" || *iter == "sport" || *iter == "dport") {
            const std::string current_token = *iter;
            if (++iter == tokens.end()) {
                std::cerr << "Invalid protocol/port format. " << std::endl;
                return std::unexpected(false);
            }

            const auto sub_tokens = util::tokenize_string(*iter, ':');
            if (sub_tokens.size() != 2) {
                std::cerr << "Invalid protocol/port format. " << std::endl;
                return std::unexpected(false);
            }

            const int range_low = util::string_to_int(*(sub_tokens.begin()));
            const int range_high = util::string_to_int(*(++sub_tokens.begin()));
            if ((range_low < 0 || range_high < 0) ||
                (current_token == "proto" && (range_low > 0xFF || range_high > 0xFF)) ||
                ((current_token == "sport" || current_token == "dport") && (range_low > 0xFFFF || range_high > 0xFFFF))) {
                std::cerr << "Invalid protocol range value. " << std::endl;
                return std::unexpected(false);
            }

            if (current_token == "proto") {
                proto_low = static_cast<uint8_t>(range_low);
                proto_high = static_cast<uint8_t>(range_high);
                is_proto_present = true;
            } else if (current_token == "sport") {
                src_port_low = static_cast<uint16_t>(range_low);
                src_port_high = static_cast<uint16_t>(range_high);
                is_src_port_present = true;
            } else if (current_token == "dport") {
                dst_port_low = static_cast<uint16_t>(range_low);
                dst_port_high = static_cast<uint16_t>(range_high);
                is_dst_port_present = true;
            }
        } else if (*iter == "sip" || *iter == "dip") {
            const std::string current_token = *iter;
            if (++iter == tokens.end()) {
                std::cerr << "Invalid sip/dip format. " << std::endl;
                return std::unexpected(false);
            }

            const auto sub_tokens = util::tokenize_string(*iter, '/');
            if (sub_tokens.size() != 2) {
                std::cerr << "Invalid sip/dip format. " << std::endl;
                return std::unexpected(false);
            }

            uint8_t ip_buffer[IPV6_ADDRESS_SIZE] = {0};
            if (inet_pton(AF_INET, sub_tokens.begin()->data(), ip_buffer) <= 0) {
                if (inet_pton(AF_INET6, sub_tokens.begin()->data(), ip_buffer) <= 0) {
                    std::cerr << "Invalid sip/dip format. " << std::endl;
                    return std::unexpected(false);
                } else {
                    int ipv6_mask = util::string_to_int(*(++sub_tokens.begin()));
                    if (ipv6_mask < 0 || ipv6_mask > 128) {
                        std::cerr << "Invalid ipv6 mask. " << std::endl;
                        return std::unexpected(false);
                    }

                    if (current_token == "sip") {
                        for (int i = 0; i < (IPV6_ADDRESS_SIZE / 4); i++) {
                            src_ip6[i] = ntohl(*reinterpret_cast<uint32_t *>(&ip_buffer[i * 4]));
                            src_ip6_mask[i] = (ipv6_mask > 32) ? 32 : ipv6_mask;
                            ipv6_mask -= 32;
                            if (ipv6_mask < 0) {
                                ipv6_mask = 0;
                            }
                        }
                        is_src_ip_present = true;
                    } else if (current_token == "dip") {
                        for (int i = 0; i < (IPV6_ADDRESS_SIZE / 4); i++) {
                            dst_ip6[i] = ntohl(*reinterpret_cast<uint32_t *>(&ip_buffer[i * 4]));
                            dst_ip6_mask[i] = (ipv6_mask > 32) ? 32 : ipv6_mask;
                            ipv6_mask -= 32;
                            if (ipv6_mask < 0) {
                                ipv6_mask = 0;
                            }
                        }
                        is_dst_ip_present = true;
                    }

                    is_ipv6_rule = true;
                }
            } else {
                const int ipv4_mask = util::string_to_int(*(++sub_tokens.begin()));
                if (ipv4_mask < 0 || ipv4_mask > 32) {
                    std::cerr << "Invalid ipv4 mask. " << std::endl;
                    return std::unexpected(false);
                }

                const uint32_t ipv4 = *reinterpret_cast<uint32_t *>(ip_buffer);
                if (current_token == "sip") {
                    src_ip4 = ntohl(ipv4);
                    src_ip4_mask = ipv4_mask;
                    is_src_ip_present = true;
                } else if (current_token == "dip") {
                    dst_ip4 = ntohl(ipv4);
                    dst_ip4_mask = ipv4_mask;
                    is_dst_ip_present = true;
                }
                is_ipv4_rule = true;
            }
        }

        ++iter;
    }

    if (!is_priority_present) {
        std::cerr << "Rule priority is missing. " << std::endl;
        return std::unexpected(false);
    }

    if (!is_proto_present && !is_src_port_present && !is_dst_port_present && !is_src_ip_present && !is_dst_ip_present) {
        std::cerr << "Rule must contain one or more of these fields: proto, src_port, dst_port, src_ip, dst_ip. " << std::endl;
        return std::unexpected(false);
    }

    std::memset(&rule_ip4, 0x00, sizeof(rule_ip4));
    std::memset(&rule_ip6, 0x00, sizeof(rule_ip6));

    // Create IPv4 rule structure.
    rule_ip4.data.userdata = 0xDEADFEED;
    rule_ip4.data.priority = rule_priority;
    rule_ip4.data.category_mask = is_category_present ? (1 << category) : 1;

    rule_ip4.field[0].value.u8 = proto_low;
    rule_ip4.field[0].mask_range.u8 = proto_high;

    rule_ip4.field[1].value.u32 = src_ip4;
    rule_ip4.field[1].mask_range.u32 = src_ip4_mask;

    rule_ip4.field[2].value.u32 = dst_ip4;
    rule_ip4.field[2].mask_range.u32 = dst_ip4_mask;

    rule_ip4.field[3].value.u16 = src_port_low;
    rule_ip4.field[3].mask_range.u16 = src_port_high;

    rule_ip4.field[4].value.u16 = dst_port_low;
    rule_ip4.field[4].mask_range.u16 = dst_port_high;

    // Create IPv6 rule structure.
    rule_ip6.data.userdata = 0xDEADFEED;
    rule_ip6.data.priority = rule_priority;
    rule_ip6.data.category_mask = is_category_present ? (1 << category) : 1;

    rule_ip6.field[0].value.u8 = proto_low;
    rule_ip6.field[0].mask_range.u8 = proto_high;

    rule_ip6.field[1].value.u32 = src_ip6[0];
    rule_ip6.field[1].mask_range.u32 = src_ip6_mask[0];
    rule_ip6.field[2].value.u32 = src_ip6[1];
    rule_ip6.field[2].mask_range.u32 = src_ip6_mask[1];
    rule_ip6.field[3].value.u32 = src_ip6[2];
    rule_ip6.field[3].mask_range.u32 = src_ip6_mask[2];
    rule_ip6.field[4].value.u32 = src_ip6[3];
    rule_ip6.field[4].mask_range.u32 = src_ip6_mask[3];

    rule_ip6.field[5].value.u32 = dst_ip6[0];
    rule_ip6.field[5].mask_range.u32 = dst_ip6_mask[0];
    rule_ip6.field[6].value.u32 = dst_ip6[1];
    rule_ip6.field[6].mask_range.u32 = dst_ip6_mask[1];
    rule_ip6.field[7].value.u32 = dst_ip6[2];
    rule_ip6.field[7].mask_range.u32 = dst_ip6_mask[2];
    rule_ip6.field[8].value.u32 = dst_ip6[3];
    rule_ip6.field[8].mask_range.u32 = dst_ip6_mask[3];

    rule_ip6.field[9].value.u16 = src_port_low;
    rule_ip6.field[9].mask_range.u16 = src_port_high;

    rule_ip6.field[10].value.u16 = dst_port_low;
    rule_ip6.field[10].mask_range.u16 = dst_port_high;

    if (is_ipv4_rule && !is_ipv6_rule) {
        return &rule_ip4;
    } else if (!is_ipv4_rule && is_ipv6_rule) {
        return &rule_ip6;
    } else if (!is_ipv4_rule && !is_ipv6_rule) {
        return std::make_pair(&rule_ip4, &rule_ip6);
    }

    std::cerr << "Rule contains both ipv4 and ipv6 address. Invalid rule. " << std::endl;
    return std::unexpected(false);
}

static uint64_t current_ctx_id = 0;

std::expected<rte_acl_ctx *, std::string> create_acl_context(const uint32_t rule_size,
                                                             const uint32_t rule_num_fields,
                                                             const uint32_t max_rule_num,
                                                             const rte_acl_field_def *const rule_field_defs,
                                                             const rte_acl_rule* rule_data) {
    
    rte_acl_param acl_param = {};
    const std::string acl_ctx_name = "acl_ctx_" + std::to_string(++current_ctx_id);

    acl_param.name = acl_ctx_name.c_str();
    acl_param.socket_id = rte_socket_id();
    acl_param.rule_size = rule_size;
    acl_param.max_rule_num = max_rule_num;
    rte_acl_ctx* acl_ctx = rte_acl_create(&acl_param);
    if (!acl_ctx) {
        return std::unexpected("Failed to create acl context. ");
    }

    int return_val = rte_acl_add_rules(acl_ctx, rule_data, max_rule_num);
    if (return_val < 0) {
        rte_acl_free(acl_ctx);
        return std::unexpected("Unable to add rules to acl context. Return code: " + std::to_string(return_val));
    }

    rte_acl_config acl_build_param = {};
    acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
    acl_build_param.num_fields = rule_num_fields;
    std::memcpy(&acl_build_param.defs, rule_field_defs, (rule_num_fields * sizeof(rte_acl_field_def)));

    return_val = rte_acl_build(acl_ctx, &acl_build_param);
    if (return_val != 0) {
        rte_acl_free(acl_ctx);
        return std::unexpected("Unable to build acl context. Return code: " + std::to_string(return_val));
    }

    return acl_ctx;
}

int main(int argc, char *argv[])
{
    // Initialising the DPDK EAL (Environment Abstraction Layer).
    int32_t return_val = rte_eal_init(argc, argv);
    if (return_val < 0) {
        std::cerr << "Unable to initialize DPDK EAL (Environment Abstraction Layer). Error code: " << rte_errno << std::endl;
        exit(1);
    }

    // Create some rules.
    // pri: Rule priority.
    // category: Rule category or rule group. A rule category or group contains one or more rules.
    // proto: Transport layer protocol (UDP, TCP, SCTP etc.). User can specify the range of protocols.
    // sport: Source port of the packet. User can specify the range of source ports.
    // dport: Destination port of the packet. User can specify the range of destination ports.
    // sip: Source ip of the packet. User can specify the IP mask to select the IP range.
    // dip: Destination ip of the packet. User can specify the IP mask to select the IP range.
    const std::list<std::string> rules = {
        "pri 1 category 0 proto 17:17 sport 5060:5060 dport 5060:5060 sip 192.168.1.1/32 dip 192.168.1.2/32",
        "pri 1 category 0 proto 17:17 sport 6672:6672 dport 5555:5555 sip 192.168.100.1/32 dip 192.168.100.2/32",
        "pri 1 category 3 proto 17:17 sport 5060:5060 dport 5060:5060 sip 2001:db8:0::1/126 dip 2001:fa8:0::1/126"
    };

    // Parse the rule strings and create rule structures.
    std::vector<acl4_rule> acl4_rules;
    std::vector<acl6_rule> acl6_rules;
    for (const auto& rule : rules) {
        const auto result = parse_rule(rule);
        if (result.has_value()) {
            if (std::holds_alternative<acl4_rule *>(result.value())) {
                acl4_rules.emplace_back(*std::get<acl4_rule *>(result.value()));
            } else if (std::holds_alternative<acl6_rule *>(result.value())) {
                acl6_rules.emplace_back(*std::get<acl6_rule *>(result.value()));
            } else if (std::holds_alternative<std::pair<acl4_rule *, acl6_rule *>>(result.value())) {
                const auto res = std::get<std::pair<acl4_rule *, acl6_rule *>>(result.value());
                acl4_rules.emplace_back(*res.first);
                acl6_rules.emplace_back(*res.second);
            }
        }
    }

    printf("Total rules found: IPv4 [%lu] IPv6[%lu] \n", acl4_rules.size(), acl6_rules.size());

    // Creating a ACL context from IPv4 rules.
    auto result1 = create_acl_context(RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)), 
                                     RTE_DIM(ipv4_defs), 
                                     acl4_rules.size(), 
                                     ipv4_defs, 
                                     reinterpret_cast<const rte_acl_rule *>(acl4_rules.data()));
    if (!result1.has_value()) {
        std::cerr << result1.error() << std::endl;
        exit(2);
    }

    std::cout << "Succesfully created rule context for IPv4. " << std::endl;
    rte_acl_ctx *const ipv4_acl_ctx = result1.value();

    // Creating a ACL context from IPv6 rules.
    auto result2 = create_acl_context(RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs)), 
                                      RTE_DIM(ipv6_defs), 
                                      acl6_rules.size(), 
                                      ipv6_defs, 
                                      reinterpret_cast<const rte_acl_rule *>(acl6_rules.data()));
    if (!result2.has_value()) {
        std::cerr << result2.error() << std::endl;
        exit(2);
    }

    std::cout << "Succesfully created rule context for IPv6. " << std::endl;
    rte_acl_ctx *const ipv6_acl_ctx = result2.value();

    // Create a memory pool of memory buffers.
    rte_mempool *const memory_pool = rte_pktmbuf_pool_create("mempool_1", 1023, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!memory_pool) {
        std::cerr << "Unable to create memory pool. " << std::endl;
        exit(3);
    }

    // Creating a sample IPv4 packet and pass it to the IPv4 acl context.
    // The sample IPv4 packet will have protocol: 17 (UDP), source ip: 192.168.1.1, dest ip: 192.168.1.2, source port: 5060, dest port: 5060.
    auto packet_result = create_packet(memory_pool, 17, "192.168.1.1", "192.168.1.2", 5060, 5060, IP_VERSION::IPV4);
    if (!packet_result.has_value()) {
        std::cerr << packet_result.error();
    }

    rte_mbuf *const ipv4_packet = packet_result.value();

    // Now we will pass our sample packet to the IPv4 ACL context and check if this packet passes any rule.
    constexpr uint8_t NUM_PKTS = 1;
    const uint8_t *ipv4_acl_input[NUM_PKTS] = {rte_pktmbuf_mtod(ipv4_packet, uint8_t *) + sizeof(rte_ether_hdr)};

    // ipv4_acl_result array will hold the result for the input packets for each category.
    // result_index = (p * max_categories) + c  (Where p is the packet number and c is the category number.)
    uint32_t ipv4_acl_result[NUM_PKTS * DEFAULT_MAX_CATEGORIES] = {0};  
    int ret = rte_acl_classify(ipv4_acl_ctx, ipv4_acl_input, ipv4_acl_result, NUM_PKTS, DEFAULT_MAX_CATEGORIES);
    if (ret) {
        std::cerr << "IPv4 ACL classification failed. Errno: " << ret << std::endl;
        exit(5);
    }

    const auto print_acl_result = [](const std::span<uint32_t> acl_result) -> void {
        std::cout << "ACL Result: [ ";
        for (const auto val : acl_result) {
            std::cout << std::hex << std::showbase << std::uppercase << val << " ";
        }
        std::cout << "]" << std::endl;
    };

    std::cout << "IPv4 ";
    print_acl_result(ipv4_acl_result);

    // Creating a sample IPv6 packet and pass it to the IPv6 acl context.
    // The sample IPv6 packet will have protocol: 17 (UDP), source ip: , dest ip: , source port: 5060, dest port: 5060.
    auto ipv6_packet_result = create_packet(memory_pool, 17, "2001:db8:0::3", "2001:fa8:0::2", 5060, 5060, IP_VERSION::IPV6);
    if (!ipv6_packet_result.has_value()) {
        std::cerr << ipv6_packet_result.error();
    }

    rte_mbuf *const ipv6_packet = ipv6_packet_result.value();

    // Now we will pass our sample packet to the IPv6 ACL context and check if this packet passes any rule.
    const uint8_t *ipv6_acl_input[NUM_PKTS] = {rte_pktmbuf_mtod(ipv6_packet, uint8_t *) + sizeof(rte_ether_hdr)};

    // ipv4_acl_result array will hold the result for the input packets for each category.
    // result_index = (p * max_categories) + c  (Where p is the packet number and c is the category number.)
    uint32_t ipv6_acl_result[NUM_PKTS * DEFAULT_MAX_CATEGORIES] = {0};  
    ret = rte_acl_classify(ipv6_acl_ctx, ipv6_acl_input, ipv6_acl_result, NUM_PKTS, DEFAULT_MAX_CATEGORIES);
    if (ret) {
        std::cerr << "IPv6 ACL classification failed. Errno: " << ret << std::endl;
        exit(5);
    }

    std::cout << "IPv6 ";
    print_acl_result(ipv6_acl_result);

    rte_pktmbuf_free(ipv4_packet);
    rte_pktmbuf_free(ipv6_packet);
    rte_acl_free(ipv4_acl_ctx);
    rte_acl_free(ipv6_acl_ctx);
    rte_eal_cleanup();
    
    return 0;
}