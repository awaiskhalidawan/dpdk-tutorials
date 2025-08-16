#include <iostream>
#include <fstream>
#include <filesystem>
#include <rule_manager.hpp>
#include <util.hpp>
#include <cstring>
#include <arpa/inet.h>
#include <thread>

rule_manager::rule_manager() : is_initialized(false), current_rule_id(0), exit_indicator(false) {

}

rule_manager& rule_manager::get_instance() {
    static rule_manager rule_manager_obj;
    return rule_manager_obj;
}
	
rule_manager::~rule_manager() {

}

void rule_manager::stop() {
    exit_indicator.store(true, std::memory_order_relaxed);
}

void rule_manager::cleanup() {
    acl4_rules.clear();

    for (const auto [port_id, num_queues] : this->port_and_queue_info_list) {
        for (uint16_t i = 0; i < num_queues; ++i) {
            rte_acl_free(acl_ctx_info_ipv4[port_id][i].acl_ctx_data_plane);
            rte_acl_free(acl_ctx_info_ipv4[port_id][i].acl_ctx_rule_manager);
        }
    }
}

std::expected<acl4_rule, bool> rule_manager::parse_ipv4_rule(const std::string &rule_str) {
    acl4_rule rule = {0};
    rule.data.userdata = 0xDEADFEED;

    const auto tokens = util::tokenize_string(rule_str, ' ');

    for (auto iter = tokens.begin(); iter != tokens.end();) {
        if (*iter == "pri") {
            if (++iter == tokens.end()) {
                std::cerr << "Invalid rule priority format. " << std::endl;
                return std::unexpected(false);
            }

            const int32_t rule_pri = util::string_to_int(*iter);
            if (rule_pri < 0) {
                std::cerr << "Unable to parse rule priority. " << std::endl;
                return std::unexpected(false);
            }

            rule.data.priority = rule_pri;
            rule.data.category_mask = (1 << CATEGORY_0);
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
                return std::unexpected(false);
            }

            const auto sub_tokens = util::tokenize_string(*iter, '/');
            if (sub_tokens.size() != 2) {
                std::cerr << "Invalid sip/dip format. " << std::endl;
                return std::unexpected(false);
            }

            uint8_t ip_buffer[16] = {0};
            if (inet_pton(AF_INET, sub_tokens.begin()->data(), ip_buffer) <= 0) {
                if (inet_pton(AF_INET6, sub_tokens.begin()->data(), ip_buffer) <= 0) {
                    std::cerr << "Invalid sip/dip format. " << std::endl;
                    return std::unexpected(false);
                } else {
                    std::cerr << "Ipv6 currently not supported ... " << std::endl;
                    return std::unexpected(false);
                }
            } else {
                const int ipv4_mask = util::string_to_int(*(++sub_tokens.begin()));
                if (ipv4_mask < 0 || ipv4_mask > 32) {
                    std::cerr << "Invalid ipv4 mask. " << std::endl;
                    return std::unexpected(false);
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

    return rule;
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
    if (!std::filesystem::exists(RULE_STORAGE_FILE_PATH)) {
        std::cerr << "Rule storage file not found: " << RULE_STORAGE_FILE_PATH << std::endl;
        return false;
    }
    
    std::ifstream rule_storage_file(RULE_STORAGE_FILE_PATH);
    if (!rule_storage_file.is_open()) {
        std::cerr << "Unable to open the rule storage file. " << std::endl;
        return false;
    }

    std::string line;    
    std::list<std::string> rules_list;

    auto tp0 = std::chrono::high_resolution_clock::now();
    while (std::getline(rule_storage_file, line)) {
        rules_list.push_back(line);
    }

    auto tp1 = std::chrono::high_resolution_clock::now();
    std::cout << "Rules file reading time (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(tp1 - tp0).count() << std::endl;

    tp0 = std::chrono::high_resolution_clock::now();    
    for (const auto &rule_str : rules_list) {
        // Process each line entry in rule storage file.
        // std::cout << "Processing rule: " << rule_str << std::endl;
        
        auto parse_result = parse_ipv4_rule(rule_str);
        if (!parse_result.has_value()) {
            return false;
        }

        auto result = map_rule_id_vs_acl4_rule.emplace(++current_rule_id, parse_result.value());
        if (!result.second) {
            std::cerr << "Unable to insert rule object in the acl4 rule map. " << std::endl;
            return false;
        }
    }

    tp1 = std::chrono::high_resolution_clock::now();
    std::cout << rules_list.size() << " rules parsing time (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(tp1 - tp0).count() << std::endl;
    
    if (map_rule_id_vs_acl4_rule.size()) {
        tp0 = std::chrono::high_resolution_clock::now();
        acl4_rules.clear();
        acl4_rules.resize(map_rule_id_vs_acl4_rule.size());

        uint32_t count = 0;
        for (const auto &kv : map_rule_id_vs_acl4_rule) {
            acl4_rules[count++] = kv.second;
        }

        tp1 = std::chrono::high_resolution_clock::now();
        std::cout << "Rules array creation time (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(tp1 - tp0).count() << std::endl;

        tp0 = std::chrono::high_resolution_clock::now();        
        rte_acl_param acl_param{0};
        rte_acl_config acl_build_param{0};
        rte_acl_ctx *acl_ctx{nullptr};

        for (const auto [port_id, num_queues] : this->port_and_queue_info_list) {
            for (uint16_t i = 0; i < num_queues; ++i) {
                std::memset(&acl_param, 0x00, sizeof(acl_param));
                std::string acl_ctx_name = "acl_ctx_" + std::to_string(port_id) + "_" + std::to_string(i) + "_dataplane";
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
                acl_ctx_info_ipv4[port_id][i].acl_ctx_data_plane = acl_ctx;
                acl_ctx = nullptr;

                acl_ctx_name = "acl_ctx_" + std::to_string(port_id) + "_" + std::to_string(i) + "_rule_manager";
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
                acl_ctx_info_ipv4[port_id][i].acl_ctx_rule_manager = acl_ctx;
                acl_ctx = nullptr;

                std::memset(&acl_build_param, 0x00, sizeof(acl_build_param));
                acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
                acl_build_param.num_fields = RTE_DIM(ipv4_defs);
                std::memcpy(&acl_build_param.defs, ipv4_defs, sizeof(ipv4_defs));

                return_val = rte_acl_build(acl_ctx_info_ipv4[port_id][i].acl_ctx_data_plane, &acl_build_param);
                if (return_val != 0) {
                    std::cerr << "Unable to build data plance acl context. Return value: " << return_val << std::endl;
                    return false;
                }

                return_val = rte_acl_build(acl_ctx_info_ipv4[port_id][i].acl_ctx_rule_manager, &acl_build_param);
                if (return_val != 0) {
                    std::cerr << "Unable to build rule manager acl context. Return val: " << return_val << std::endl;
                    return false;
                }
            }
        }
        
        tp1 = std::chrono::high_resolution_clock::now();
        std::cout << "Rules context creation time (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(tp1 - tp0).count() << std::endl;
    }

    is_initialized = true;

    /*// Perform classification test.
    uint8_t start_idx = 9;
    uint8_t data[100] = {0};
    uint32_t src_ip = rte_cpu_to_be_32(RTE_IPV4(192,168,1,1));
    uint32_t dst_ip = rte_cpu_to_be_32(RTE_IPV4(192,168,1,2));
    uint16_t src_port = rte_cpu_to_be_16(5061);
    uint16_t dst_port = rte_cpu_to_be_16(5061);

    data[start_idx + 0] = 17;    
    std::memcpy(&data[start_idx + 3], &src_ip, sizeof(src_ip));
    std::memcpy(&data[start_idx + 7], &dst_ip, sizeof(dst_ip));
    std::memcpy(&data[start_idx + 11], &src_port, sizeof(src_port));
    std::memcpy(&data[start_idx + 13], &dst_port, sizeof(dst_port));

    const uint8_t *inputs[] = {
        (const uint8_t *)data
    };
    uint32_t results[1 * 1] = {0};

    int return_val = rte_acl_classify(acl_ctx_info[0][0].acl_ctx_rule_manager, inputs, results, 1, 1);
    printf("rte_acl_classify completed. Return value: %d \n", return_val);
    //*/

    return true;
}

rte_acl_ctx* rule_manager::get_data_plane_acl_ctx_ipv4(const uint32_t port_id, const uint32_t queue_id) {
    acl_context_info &acl_ctx = acl_ctx_info_ipv4[port_id][queue_id];

    if (acl_ctx.is_acl_ctx_rule_manager_updated.load(std::memory_order_relaxed)) {
        // The ACL context is updated by rule manager. Swap the data plane acl context with rule manager acl context.
        std::swap(acl_ctx.acl_ctx_data_plane, acl_ctx.acl_ctx_rule_manager);
        acl_ctx.is_acl_ctx_rule_manager_updated.store(false, std::memory_order_relaxed);
    }

    return acl_ctx.acl_ctx_data_plane;
}

void rule_manager::check_and_update_acl_contexts() {
    while (!exit_indicator.load(std::memory_order_relaxed)) {
        // Check for received rules and add them in the map.

        // Check if the data plane contexts are yet to be updated or not.
        bool is_acl4_ctx_rule_manager_updated = false;
        for (const auto [port_id, num_queues] : this->port_and_queue_info_list) {
            for (uint16_t i = 0; i < num_queues; ++i) {
                acl_context_info &acl_ctx_info = acl_ctx_info_ipv4[port_id][i];
                if (acl_ctx_info.is_acl_ctx_rule_manager_updated.load(std::memory_order_relaxed)) {
                    is_acl4_ctx_rule_manager_updated = true;
                }
            }
        }

        if (!is_acl4_ctx_rule_manager_updated && is_acl4_map_updated) {
            is_acl4_map_updated = false;

            acl4_rules.clear();
            acl4_rules.resize(map_rule_id_vs_acl4_rule.size());
            uint64_t count = 0;
            for (const auto &kv : map_rule_id_vs_acl4_rule) {
                acl4_rules[count++] = kv.second;
            }

            rte_acl_config acl_build_param = {0};
            std::memset(&acl_build_param, 0x00, sizeof(acl_build_param));
            acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
            acl_build_param.num_fields = RTE_DIM(ipv4_defs);
            std::memcpy(&acl_build_param.defs, ipv4_defs, sizeof(ipv4_defs));

            int return_val {0};
            for (const auto [port_id, num_queues] : this->port_and_queue_info_list) {
                for (uint16_t i = 0; i < num_queues; ++i) {
                    rte_acl_ctx *acl_ctx = acl_ctx_info_ipv4[port_id][i].acl_ctx_rule_manager;

                    rte_acl_reset(acl_ctx);
                    if (rte_acl_add_rules(acl_ctx, reinterpret_cast<const rte_acl_rule *>(acl4_rules.data()), acl4_rules.size()) < 0) {
                        std::cerr << "Unable to add rules to acl context. " << std::endl;
                        continue;
                    }

                    return_val = rte_acl_build(acl_ctx, &acl_build_param);
                    if (return_val != 0) {
                        std::cerr << "Unable to build rule manager acl context. Return value: " << return_val << std::endl;
                        continue;
                    }
                }
            }

            // All the acl contexts are updated successfully. Set the flag to notify to data plane.
            for (const auto [port_id, num_queues] : this->port_and_queue_info_list) {
                for (uint16_t i = 0; i < num_queues; ++i) {
                    acl_context_info &acl_ctx_info = acl_ctx_info_ipv4[port_id][i];
                    acl_ctx_info.is_acl_ctx_rule_manager_updated.store(true, std::memory_order_relaxed);
                }
            }
        } else {
            using namespace std::literals;
            std::this_thread::sleep_for(50ms);
        }
    }

    std::cout << "Exiting rule manager thread routine. " << std::endl;
}
