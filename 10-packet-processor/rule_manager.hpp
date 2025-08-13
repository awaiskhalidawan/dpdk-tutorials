#pragma once

#include <atomic>
#include <list>
#include <rte_acl.h>
#include <common.hpp>
#include <vector>
#include <spin_lock.hpp>
#include <rte_ip4.h>
#include <unordered_map>

static const std::string RULE_STORAGE_FILE_PATH = "/tmp/rule_storage_file.txt";
constexpr uint8_t CATEGORY_0 = 0;
constexpr uint8_t DEFAULT_MAX_CATEGORIES = 1;

static struct rte_acl_field_def ipv4_defs[5] = {
    /* first input field - always one byte long. */
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof (uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = offsetof (struct rte_ipv4_hdr, next_proto_id),
    },

    /* next input field (IPv4 source address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset = offsetof (struct rte_ipv4_hdr, src_addr),
    },

    /* next input field (IPv4 destination address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset = offsetof (struct rte_ipv4_hdr, dst_addr),
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
        .offset = offsetof (struct rte_ipv4_hdr, dst_addr) + sizeof(uint32_t),
    },

    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 4,
        .input_index = 3,
        .offset = offsetof (struct rte_ipv4_hdr, dst_addr) + sizeof(uint32_t) + sizeof(uint16_t),
    },
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));

struct alignas(RTE_CACHE_LINE_SIZE) acl_context_info {
	rte_acl_ctx *acl_ctx_data_plane {nullptr};
	rte_acl_ctx *acl_ctx_rule_manager {nullptr};
	std::atomic<bool> is_acl_ctx_rule_manager_updated {false};
	spin_lock acl_ctx_lock;
};


class rule_manager {
private:
	rule_manager();

    std::vector<acl4_rule> acl4_rules;
	
    bool is_initialized {false};

    std::unordered_map<uint64_t, acl4_rule> map_rule_id_vs_acl4_rule;

    uint64_t current_rule_id {0};

public:
	static rule_manager& get_instance();
	
	~rule_manager();
	
	bool initialize(const std::list<std::pair<uint32_t, uint32_t>> &port_and_queue_info);

    void cleanup();

    rte_acl_ctx* get_data_plane_acl_ctx_ipv4(const uint32_t port_id, const uint32_t queue_id);

    void check_and_update_acl_contexts();
	
	acl_context_info acl_ctx_info_ipv4[RTE_MAX_ETHPORTS][MAX_QUEUES];

    std::list<std::pair<uint32_t, uint32_t>> port_and_queue_info_list;
};
