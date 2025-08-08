#include <iostream>
#include <fstream>
#include <filesystem>
#include <rule_manager.hpp>
#include <util.hpp>
#include <cstring>
#include <arpa/inet.h>

rule_manager::rule_manager() : is_initialized(false) {

}

rule_manager& rule_manager::get_instance() {
    static rule_manager rule_manager_obj;
    return rule_manager_obj;
}
	
rule_manager::~rule_manager() {

}

void rule_manager::cleanup() {
    acl4_rules.clear();

    for (const auto [port_id, num_queues] : this->port_and_queue_info_list) {
        for (uint16_t i = 0; i < num_queues; ++i) {
            rte_acl_free(acl_ctx_info[port_id][i].acl_ctx_data_plane);
            rte_acl_free(acl_ctx_info[port_id][i].acl_ctx_rule_manager);
        }
    }
}

bool rule_manager::initialize(const std::list<std::pair<uint32_t, uint32_t>> &port_and_queue_info_list) {
    if (is_initialized) {
        return true;
    }
    
    // Check port and queue indexes.
    for (const auto &[port_id, num_queues] : port_and_queue_info_list) {
        if (port_id >= RTE_MAX_ETHPORTS || num_queues >= MAX_QUEUES) {
            return false;
        }
    }

    this->port_and_queue_info_list = port_and_queue_info_list;

    // Read the file to load the stored rules.
    if (std::filesystem::exists(RULE_STORAGE_FILE_PATH)) {
        std::ifstream rule_storage_file(RULE_STORAGE_FILE_PATH);
        if (!rule_storage_file.is_open()) {
            std::cerr << "Unable to open the rule storage file. " << std::endl;
            return false;
        }

        std::string line;
        int32_t previous_rule_id = -1;
        while (std::getline(rule_storage_file, line)) {
            // Process each line entry in rule storage file.
            std::cout << "Processing rule: " << line << std::endl;
            const auto tokens = util::tokenize_string(line, ' ');

            // Create a new rule in the rule list.
            auto &rule = acl4_rules.emplace_back(acl4_rule());
            std::memset(&rule, 0x00, sizeof(rule));

            for (auto iter = tokens.begin(); iter != tokens.end(); ) {
                if (iter == tokens.begin()) {
                    // The first token must be the rule id.
                    const int32_t rule_id = util::string_to_int(*iter);
                    if (rule_id < 0) {
                        std::cerr << "Unable to parse rule id. " << std::endl;
                        return false;
                    }

                    if (rule_id <= previous_rule_id) {
                        std::cerr << "Incorrect/duplicate rule id found. " << std::endl;
                        return false;
                    }
                    previous_rule_id = rule_id;
                    rule.data.userdata = rule_id & 0xFFFF;
                } else if (*iter == "pri") {
                    if (++iter == tokens.end()) {
                        std::cerr << "Invalid rule priority format. " << std::endl;
                        return false;
                    }
                    const int32_t rule_pri = util::string_to_int(*iter);
                    if (rule_pri < 0) {
                        std::cerr << "Unable to parse rule priority. " << std::endl;
                        return false;
                    }
                    rule.data.priority = rule_pri;
                    rule.data.category_mask = 1 << CATEGORY_0;
                } else if (*iter == "proto" || *iter == "sport" || *iter == "dport") {
                    const std::string current_token = *iter;
                    if (++iter == tokens.end()) {
                        std::cerr << "Invalid protocol/port format. " << std::endl;
                        return false;
                    }
                    const auto sub_tokens = util::tokenize_string(*iter, ':');
                    if (sub_tokens.size() != 2) {
                        std::cerr << "Invalid protocol/port format. " << std::endl;
                        return false;
                    }
                    const int range_low = util::string_to_int(*(sub_tokens.begin()));
                    const int range_high = util::string_to_int(*(++sub_tokens.begin()));
                    if ((range_low < 0 || range_high < 0) || 
                        (current_token == "proto" && (range_low > 0xFF || range_high > 0xFF)) ||
                        ((current_token == "sport" || current_token == "dport") && (range_low > 0xFFFF || range_high > 0xFFFF))) {
                        std::cerr << "Invalid protocol range value. " << std::endl;
                        return false;
                    }
                    if (current_token == "proto") {
                        rule.field[0].value.u8 = static_cast<uint8_t>(range_low);
                        rule.field[0].mask_range.u8 = static_cast<uint8_t>(range_high);
                    } else if (current_token == "sport") {
                        rule.field[3].value.u16 = static_cast<uint16_t>(range_low);
                        rule.field[3].mask_range.u16 = static_cast<uint16_t>(range_high);
                    } else if (current_token == "dport") {
                        rule.field[4].value.u16 = static_cast<uint16_t>(range_low);
                        rule.field[4].mask_range.u16 = static_cast<uint16_t>(range_high);
                    }
                } else if (*iter == "sip" || *iter == "dip") {
                    const std::string current_token = *iter;
                    if (++iter == tokens.end()) {
                        std::cerr << "Invalid sip/dip format. " << std::endl;
                        return false;
                    }
                    const auto sub_tokens = util::tokenize_string(*iter, '/');
                    if (sub_tokens.size() != 2) {
                        std::cerr << "Invalid sip/dip format. " << std::endl;
                        return false;
                    }
                    uint8_t ip_buffer[16] = {0};
                    if (inet_pton(AF_INET, sub_tokens.begin()->data(), ip_buffer) <= 0) {
                        if (inet_pton(AF_INET6, sub_tokens.begin()->data(), ip_buffer) <= 0) {
                            std::cerr << "Invalid sip/dip format. " << std::endl;
                            return false;
                        } else {
                            std::cerr << "Ipv6 currently not supported ... " << std::endl;
                            return false;
                        }
                    } else {
                        const int ipv4_mask = util::string_to_int(*(++sub_tokens.begin()));
                        if (ipv4_mask < 0 || ipv4_mask > 32) {
                            std::cerr << "Invalid ipv4 mask. " << std::endl;
                            return false;
                        }
                        const uint32_t ipv4 = *reinterpret_cast<uint32_t *>(ip_buffer);
                        if (current_token == "sip") {
                            rule.field[1].value.u32 = ntohl(ipv4);
                            rule.field[1].mask_range.u32 = ipv4_mask;
                        } else if (current_token == "dip") {
                            rule.field[2].value.u32 = ntohl(ipv4);
                            rule.field[2].mask_range.u32 = ipv4_mask;
                        }
                    }
                }
                
                ++iter;
            }
        }

        rte_acl_param acl_param {0};          
        rte_acl_config acl_build_param {0};
        rte_acl_ctx *acl_ctx {nullptr};

        for (const auto [port_id, num_queues] : this->port_and_queue_info_list) {
            for (uint16_t i = 0; i < num_queues; ++i) {
                std::memset(&acl_param, 0x00, sizeof(acl_param));
                std::string acl_ctx_name = "acl_ctx_" + std::to_string(port_id) + "_" + std::to_string(i) + "_dp";
                acl_param.name = acl_ctx_name.c_str();
                acl_param.socket_id = rte_socket_id();
                acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));
                acl_param.max_rule_num = acl4_rules.size();
                acl_ctx = rte_acl_create(&acl_param);
                if (!acl_ctx) {
                    std::cerr << "Failed to create acl context. " << std::endl;
                    return false;
                }

                int return_val = rte_acl_add_rules(acl_ctx, reinterpret_cast<const rte_acl_rule *>(acl4_rules.data()), acl4_rules.size());
                if (return_val < 0) {
                    std::cerr << "Unable to add rules to acl context. " << std::endl;
                    rte_acl_free(acl_ctx);
                    return false;
                }
                acl_ctx_info[port_id][i].acl_ctx_data_plane = acl_ctx;
                acl_ctx = nullptr;

                acl_ctx_name = "acl_ctx_" + std::to_string(port_id) + "_" + std::to_string(i) + "_rm";
                acl_param.name = acl_ctx_name.c_str();
                acl_ctx = rte_acl_create(&acl_param);
                if (!acl_ctx) {
                    std::cerr << "Failed to create acl context. " << std::endl;
                    return false;
                }

                if (rte_acl_add_rules(acl_ctx, reinterpret_cast<const rte_acl_rule *>(acl4_rules.data()), acl4_rules.size()) < 0) {
                    std::cerr << "Unable to add rules to acl context. " << std::endl;
                    rte_acl_free(acl_ctx);
                    return false;
                }
                acl_ctx_info[port_id][i].acl_ctx_rule_manager = acl_ctx;
                acl_ctx = nullptr;

                std::memset(&acl_build_param, 0x00, sizeof(acl_build_param));
                acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
                acl_build_param.num_fields = RTE_DIM(ipv4_defs);
                std::memcpy(&acl_build_param.defs, ipv4_defs, sizeof(ipv4_defs));

                return_val = rte_acl_build(acl_ctx_info[port_id][i].acl_ctx_data_plane, &acl_build_param);
                if (return_val != 0) {
                    std::cerr << "Unable to build ACL context. Return value: " << return_val << std::endl;
                    return false;
                }

                return_val = rte_acl_build(acl_ctx_info[port_id][i].acl_ctx_rule_manager, &acl_build_param);
                if (return_val != 0) {
                    std::cerr << "Unable to build ACL context. Return val: " << return_val << std::endl;
                    return false;
                }
            }
        }    
    } else {
        return false;
    }

    is_initialized = true;
    return true;
}

rte_acl_ctx* rule_manager::get_data_plane_acl_ctx(const uint32_t port_id, const uint32_t queue_id) {
    acl_context_info &acl_ctx = acl_ctx_info[port_id][queue_id];

    if (acl_ctx.is_acl_ctx_rule_manager_updated.load(std::memory_order_relaxed)) {
        // The ACL context is updated by rule manager. Swap the data plane acl context with rule manager act context.
        acl_ctx.acl_ctx_lock.acquire();
        std::swap(acl_ctx.acl_ctx_data_plane, acl_ctx.acl_ctx_rule_manager);        
        acl_ctx.acl_ctx_lock.release();

        acl_ctx.is_acl_ctx_rule_manager_updated.store(false, std::memory_order_relaxed);
    }

    return acl_ctx.acl_ctx_data_plane;
}
	