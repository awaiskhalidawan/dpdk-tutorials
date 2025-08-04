#include <iostream>
#include <fstream>
#include <filesystem>
#include <rule_manager.hpp>
#include <util.hpp>
#include <cstring>

rule_manager::rule_manager() {

}

rule_manager& rule_manager::get_instance() {
    static rule_manager rule_manager_obj;
    return rule_manager_obj;
}
	
rule_manager::~rule_manager() {
    
}

bool rule_manager::start(const std::list<std::pair<uint32_t, uint32_t>> &port_and_queue_info_list) {
    
    // Check port and queue indexes.
    for (const auto &port_and_queue_info : port_and_queue_info_list) {
        if (port_and_queue_info.first >= RTE_MAX_ETHPORTS ||
            port_and_queue_info.second >= MAX_QUEUES) {
            return false;
        }
    }

    // Read the file to load the stored rules.
    if (std::filesystem::exists(RULE_STORAGE_FILE_PATH)) {
        std::ifstream rule_storage_file(RULE_STORAGE_FILE_PATH);
        if (!rule_storage_file.is_open()) {
            std::cerr << "Unable to open the rule storage file. " << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(rule_storage_file, line)) {
            // Process each line entry in rule storage file.
            std::cout << "Processing rule: " << line << std::endl;
            const auto tokens = util::tokenize_string(line, ' ');

            // Create a new rule in the rule list.
            auto &rule = acl4_rules.emplace_back(acl4_rule());
            std::memset(&rule, 0x00, sizeof(rule));

            for (const auto &token : tokens) {
                
            }
        }
    }

    return true;
}

bool rule_manager::stop() {

    return true;
}

rte_acl_ctx* rule_manager::get_data_plane_acl_ctx(const uint32_t port_id, const uint32_t queue_id) {
    acl_context_info &acl_ctx = acl_ctx_info[port_id][queue_id];

    if (acl_ctx.is_acl_ctx_rule_manager_updated.load(std::memory_order_relaxed)) {
        // The ACL context is updated by rule manager. Swap the data plane acl context with rule manager act context.
        acl_ctx.acl_ctx_lock.acquire();
        std::swap(acl_ctx.acl_ctx_data_plane, acl_ctx.act_ctx_rule_manager);        
        acl_ctx.acl_ctx_lock.release();

        acl_ctx.is_acl_ctx_rule_manager_updated.store(false, std::memory_order_relaxed);
    }

    return acl_ctx.acl_ctx_data_plane;
}
	