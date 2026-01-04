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

#include <iostream>
#include <csignal>
#include <vector>
#include <list>
#include <atomic>
#include <iomanip>
#include <string>
#include <utility>
#include <chrono>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
//#include <rule_manager.hpp>

constexpr uint16_t STATISTICS_DISPLAY_INTERVAL_MSEC   = 1000;        // 1 seconds.
constexpr uint32_t MEMORY_POOL_SIZE                   = 131071;      // Size of memory pool.
constexpr uint32_t RX_BURST_SIZE                      = 64;          // Rx burst size.
constexpr uint32_t TX_BURST_SIZE                      = 64;          // Tx burst size.
constexpr uint32_t NUM_QUEUE_RX_DESCRIPTORS           = 8160;        // Number of descriptors configured for Rx queue.
constexpr uint32_t NUM_QUEUE_TX_DESCRIPTORS           = 8160;        // Number of descriptors configured for Tx queue.
//constexpr uint32_t DATA_PLANE_ACL_RULES_CHECK_TIME_MS   = 1000;	     // Data plane acl rules check interval in ms.
//constexpr uint32_t RULE_MANAGER_ACL_RULES_CHECK_TIME_MS = 1000;	     // Rule manager acl rules check interval in ms.
constexpr uint32_t TX_BUFFER_FLUSH_TIME_US            = 100;	     // Transmit buffer flush time in us.

static std::atomic<bool> exit_application {false};
static std::atomic<bool> stop_printing_statistics {true}:

struct PacketReadingThreadParams 
{
    std::string input_port;
    uint16_t input_port_id {std::numeric_limits<decltype(input_port_id)>::max()};
    uint16_t output_port_id {std::numeric_limits<decltype(output_port_id)>::max()};
    uint16_t queue_id {std::numeric_limits<decltype(queue_id)>::max()};
};

struct PacketReadingThreadStatistics 
{
    std::atomic<uint64_t> rx_packets {0};
    std::atomic<uint64_t> unknown_type_rx_packets {0};
    std::atomic<uint64_t> ipv4_rx_packets {0};
    std::atomic<uint64_t> ipv6_rx_packets {0};
    std::atomic<uint64_t> ipv4_classified_packets{0};
    std::atomic<uint64_t> ipv6_classified_packets{0};
    std::atomic<uint64_t> acl_classify_failures {0};
} __rte_cache_aligned;

void terminate_signal_handler(int signal) 
{
    exit_application.store(true, std::memory_order_relaxed);
    //auto &rule_mgr = rule_manager::get_instance();
    //rule_mgr.stop();
}

void interrupt_signal_handler(int signal)
{
    stop_printing_statistics.store(true, std::memory_order_relaxed);
}

/*int manage_acl_rules(void *param)
{
    auto &rule_mgr = rule_manager::get_instance();
    rule_mgr.check_and_update_acl_contexts();
    return 0;
}*/

int read_and_process_packets_from_port(void *param)
{
    if (!param) {
        std::cerr << "Packet reading thread params are null. Cannot continue. " << std::endl;
        exit(2);
    }

    PacketReadingThreadParams *const packetReadingThreadParams = reinterpret_cast<PacketReadingThreadParams *>(param);
    const std::string input_port = packetReadingThreadParams->input_port;
    const uint16_t input_port_id = packetReadingThreadParams->input_port_id;
    const uint16_t output_port_id = packetReadingThreadParams->output_port_id;
    const uint16_t queue_id = packetReadingThreadParams->queue_id;
    delete packetReadingThreadParams;

    const std::string memzone_name = input_port + "_" + std::to_string(queue_id);
    rte_memzone *const memzone = rte_memzone_lookup(memzone_name.c_str());
    if (!memzone) {
        std::cerr << "Unable to lookup shared memory zone: " << memzone_name << std::endl;
        exit(2);
    }

    PacketReadingThreadStatistics *const packet_reading_thread_statistics = reinterpret_cast<PacketReadingThreadStatistics *>(memzone->addr);

    //auto &rule_manager = rule_manager::get_instance();
    //auto ipv4_acl_ctx = rule_manager.get_data_plane_acl_ctx_ipv4(input_port_id, queue_id);

    /*if (!ipv4_acl_ctx) {
        std::cerr << "ACL context ipv4 is not valid. Cannot continue. " << std::endl;
        exit(2);
    }*/

    printf("Starting packet reading routine. Input port: %s  Input port id: %u  Output port id: %u  Queue id: %u  Logical core id (CPU Id): %d \n", 
            input_port.c_str(), input_port_id, output_port_id, queue_id, rte_lcore_id());

    uint64_t rx_count = 0;
    uint64_t tx_count = 0;
    uint64_t tx_buffer_count = 0;
    uint16_t ipv4_rx_packet_count {0};
    uint16_t ipv6_rx_packet_count {0};
    uint16_t unknown_type_rx_packet_count {0};
    uint16_t ipv4_classified_packet_count {0};
    uint16_t ipv6_classified_packet_count {0};
    rte_mbuf *tx_packets[TX_BURST_SIZE] = {nullptr};
    rte_mbuf *rx_packets[RX_BURST_SIZE] = {nullptr};
    rte_mbuf *ipv4_rx_packets[RX_BURST_SIZE] = {nullptr};
    rte_mbuf *ipv6_rx_packets[RX_BURST_SIZE] = {nullptr};
    const uint8_t *ipv4_acl_inputs[RX_BURST_SIZE] = {nullptr};
    const uint8_t *ipv6_acl_inputs[RX_BURST_SIZE] = {nullptr};
    uint32_t ipv4_acl_results[RX_BURST_SIZE * DEFAULT_MAX_CATEGORIES] = {0};
    uint32_t ipv6_acl_results[RX_BURST_SIZE * DEFAULT_MAX_CATEGORIES] = {0};

    timespec ts {};
    auto tp0 = std::chrono::high_resolution_clock::now();
    auto tp2 = std::chrono::high_resolution_clock::now();

    auto flush_tx_buffer = [&tx_count, &tx_buffer_count, &output_port_id, &queue_id, &tx_packets]() -> void {
        tx_count = 0;
        do {
            tx_count += rte_eth_tx_burst(output_port_id, queue_id, &tx_packets[tx_count], (tx_buffer_count - tx_count));
        } while (tx_count < tx_buffer_count);
        tx_buffer_count = 0;
    };

    // Now we go into a loop to continously check the port (ethernet interface) for any incoming packets. This process is called polling.
    while (!exit_application.load(std::memory_order_relaxed)) {
	    // Check for ACL context updates periodically.
	    auto tp1 = std::chrono::high_resolution_clock::now();
	    /*if (std::chrono::duration_cast<std::chrono::milliseconds>(tp1 - tp0).count() >= DATA_PLANE_ACL_RULES_CHECK_TIME_MS) {
	        ipv4_acl_ctx = rule_manager.get_data_plane_acl_ctx_ipv4(input_port_id, queue_id);
	        tp0 = tp1;
	    }*/

        // Flush the transmit buffer perdiodically.
        if (std::chrono::duration_cast<std::chrono::microseconds>(tp1 - tp2).count() >= TX_BUFFER_FLUSH_TIME_US) {
            if (tx_buffer_count) {
                flush_tx_buffer();
            }
            tp2 = tp1;
        }

        // Read the packets from interface in bursts.
        rx_count = rte_eth_rx_burst(input_port_id, queue_id, rx_packets, RX_BURST_SIZE);
        if (rx_count == 0) {
            // No packets found. Check again.
            continue;
        }

        // Update the statistics.
        packet_reading_thread_statistics.rx_packets.fetch_add(rx_count, std::memory_order_relaxed);

        // Reset the local counters.
        ipv4_rx_packet_count = 0;
        ipv6_rx_packet_count = 0;
        unknown_type_rx_packet_count = 0;
	    ipv4_classified_packet_count = 0;
        ipv6_classified_packet_count = 0;

        for (uint16_t i = 0; i < rx_count; ++i) {
            if (rx_packets[i]->packet_type & RTE_PTYPE_L3_IPV4 == RTE_PTYPE_L3_IPV4) {
                ipv4_rx_packets[ipv4_rx_packet_count++] = std::exchange(rx_packets[i], nullptr);
            } else if (rx_packets[i]->packet_type & RTE_PTYPE_L3_IPV6 == RTE_PTYPE_L3_IPV6) {
                ipv6_rx_packets[ipv6_rx_packet_count++] = std::exchange(rx_packets[i], nullptr);
            } else {
                ++unknown_type_rx_packet_count;
            }
        }

        // Update statistics.
        packet_reading_thread_statistics.unknown_type_rx_packets.fetch_add(unknown_type_rx_packet_count, std::memory_order_relaxed);
	    packet_reading_thread_statistics.ipv4_rx_packets.fetch_add(ipv4_rx_packet_count, std::memory_order_relaxed);
        packet_reading_thread_statistics.ipv6_rx_packets.fetch_add(ipv6_rx_packet_count, std::memory_order_relaxed);
	
	    // Free the received packets which are not identified.
        rte_pktmbuf_free_bulk(rx_packets, rx_count);

        // Prefetch the packet data in the cache line.
        /*for (uint16_t i = 0; i < ipv4_rx_packet_count; ++i) {
            rte_prefetch0(rte_pktmbuf_mtod(ipv4_rx_packets[i], uint8_t *));
            ipv4_acl_inputs[i] = rte_pktmbuf_mtod(ipv4_rx_packets[i], uint8_t *) + sizeof(rte_ether_hdr);            
        }

        int return_val = rte_acl_classify(ipv4_acl_ctx, ipv4_acl_inputs, ipv4_acl_results, ipv4_rx_packet_count, DEFAULT_MAX_CATEGORIES);
        if (likely(!return_val)) {
	        for (uint16_t i = 0; i < ipv4_rx_packet_count; ++i) {
	            if (ipv4_acl_results[i]) {
		            ++ipv4_classified_packet_count;
                    tx_packets[tx_buffer_count++] = std::exchange(ipv4_rx_packets[i], nullptr);
                    if (tx_buffer_count >= TX_BURST_SIZE) {
                        flush_tx_buffer();
                    }
	            }
	        }
	        packet_reading_thread_statistics.ipv4_classified_packets.fetch_add(ipv4_classified_packet_count, std::memory_order_relaxed);
	    } else {
	        packet_reading_thread_statistics.acl_classify_failures.fetch_add(1, std::memory_order_relaxed);
	    }*/

	    rte_pktmbuf_free_bulk(ipv4_rx_packets, ipv4_rx_packet_count);
        rte_pktmbuf_free_bulk(ipv6_rx_packets, ipv6_rx_packet_count);
    }
    
    std::cout << "Exiting packet reading routine. " << std::endl;
    return 0;
}

void print_statistics(const std::string &input_port,
                      const uint16_t input_port_id,
                      const std::string &output_port,
                      const uint16_t output_port_id,
                      const uint16_t num_rx_queues,
                      const std::vector<PacketReadingThreadStatistics *> &packet_reading_thread_statistics)
{
    std::chrono::time_point<std::chrono::system_clock> t1 = std::chrono::system_clock::now();
    rte_eth_stats istats {};
    rte_eth_stats ostats {};
    static thread_local uint64_t ilast_rx_bytes = 0;
    static thread_local uint64_t ilast_tx_bytes = 0;
    static thread_local uint64_t ilast_rx_packets = 0;
    static thread_local uint64_t ilast_tx_packets = 0;
    static thread_local uint64_t olast_tx_bytes = 0;
    static thread_local uint64_t olast_tx_packets = 0;

    int return_val = rte_eth_stats_get(input_port_id, &istats);
    if (return_val) {
        printf("Unable to get input port statistics. Input port: %s  Input port id: %u  Return value: %d \n",
               input_port.c_str(), input_port_id, return_val);
        continue;
    }

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    double rx_packet_rate = (static_cast<double>(istats.ipackets - ilast_rx_packets) / (static_cast<double>(diff.count()) / 1000.0));
    ilast_rx_packets = istats.ipackets;
    double tx_packet_rate = (static_cast<double>(istats.opackets - ilast_tx_packets) / (static_cast<double>(diff.count()) / 1000.0));
    ilast_tx_packets = istats.opackets;

    double rx_data_rate = (static_cast<double>((istats.ibytes - ilast_rx_bytes) * 8) / (static_cast<double>(diff.count()) / 1000.0)) / (1024.0 * 1024.0);
    ilast_rx_bytes = istats.ibytes;
    double tx_data_rate = (static_cast<double>((istats.obytes - ilast_tx_bytes) * 8) / (static_cast<double>(diff.count()) / 1000.0)) / (1024.0 * 1024.0);
    ilast_tx_bytes = istats.obytes;

    std::cout << "\033[2J\033[1;1H";        
    std::cout << std::endl;
    std::cout << "Input Ethernet Port: " << input_port << " [" << input_port_id << "] Statistics" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << "Statistics time: " << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X") << std::endl;
    std::cout << "Receive  packets: " << istats.ipackets << std::endl;
    std::cout << "Transmit packets: " << istats.opackets << std::endl;
    std::cout << "Receive  bytes: " << istats.ibytes << std::endl;
    std::cout << "Transmit bytes: " << istats.obytes << std::endl;
    std::cout << "Receive  errors: " << istats.ierrors << std::endl;
    std::cout << "Transmit errors: " << istats.oerrors << std::endl;
    std::cout << "Rx dropped: " << istats.imissed << std::endl;
    std::cout << "Rx rx_nombuf: " << istats.rx_nombuf << std::endl;
    std::cout << std::endl;
    std::cout << "Receive  data rate (mbps): " << rx_data_rate << std::endl;
    std::cout << "Transmit data rate (mbps): " << tx_data_rate << std::endl;
    std::cout << std::fixed << std::setprecision(1) << "Receive  packet rate (pps): " << rx_packet_rate << std::endl;
    std::cout << std::fixed << std::setprecision(1) << "Transmit packet rate (pps): " << tx_packet_rate << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << std::endl;
                
    //std::cout << "Rule Manager Statistics" << std::endl;
    //std::cout << "----------------------------------------------" << std::endl;
    //std::cout << "IPv4 rules count: " << rule_manager::get_instance().acl4_context_rule_count() << std::endl;
    //std::cout << "IPv6 rules count: " << rule_manager::get_instance().acl6_context_rule_count() << std::endl;
    //std::cout << "ACL creation success count: " << rule_manager::get_instance().acl_context_creation_success_count() << std::endl;
    //std::cout << "ACL creation failure count: " << rule_manager::get_instance().acl_context_creation_failure_count() << std::endl;
    //std::cout << "----------------------------------------------" << std::endl;
    //std::cout << std::endl;

    std::cout << "Packet Reading Thread(s) Statistics" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        std::cout << "Rx queue: " << i << std::endl;
        std::cout << "     Rx packets            : " << packet_reading_thread_statistics[i]->rx_packets.load(std::memory_order_relaxed) << std::endl;
	    std::cout << "     Rx packets (unknown)  : " << packet_reading_thread_statistics[i]->unknown_type_rx_packets.load(std::memory_order_relaxed) << std::endl;            
	    std::cout << "     Rx packets (ipv4)     : " << packet_reading_thread_statistics[i]->ipv4_rx_packets.load(std::memory_order_relaxed) << std::endl;
        std::cout << "     Rx packets (ipv6)     : " << packet_reading_thread_statistics[i]->ipv6_rx_packets.load(std::memory_order_relaxed) << std::endl;
	    std::cout << "     Classified packets (ipv4)  : " << packet_reading_thread_statistics[i]->ipv4_classified_packets.load(std::memory_order_relaxed) << std::endl;
        std::cout << "     Classified packets (ipv6)  : " << packet_reading_thread_statistics[i]->ipv6_classified_packets.load(std::memory_order_relaxed) << std::endl;
	    std::cout << "     ACL classify failures      : " << packet_reading_thread_statistics[i]->acl_classify_failures.load(std::memory_order_relaxed) << std::endl;
    }
    std::cout << "----------------------------------------------" << std::endl;

    if (input_port_id != output_port_id) {
        // Display the output port statistics if the input port is different from output port.
        return_val = rte_eth_stats_get(output_port_id, &ostats);
        if (return_val) {
            printf("Unable to get output port statistics. Output port: %s  Output port id: %u  Return value: %d \n",
                   output_port.c_str(), output_port_id, return_val);
            continue;
        }

        tx_packet_rate = (static_cast<double>(ostats.opackets - olast_tx_packets) / (static_cast<double>(diff.count()) / 1000.0));
        olast_tx_packets = ostats.opackets;
        tx_data_rate = (static_cast<double>((ostats.obytes - olast_tx_bytes) * 8) / (static_cast<double>(diff.count()) / 1000.0)) / (1024.0 * 1024.0);
        olast_tx_bytes = ostats.obytes;
        std::cout << "Output Ethernet Port: " << output_port << " [" << output_port_id << "] Statistics" << std::endl;
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << "Statistics time: " << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X") << std::endl;
        std::cout << "Transmit packets: " << ostats.opackets << std::endl;
        std::cout << "Transmit bytes: " << ostats.obytes << std::endl;
        std::cout << "Transmit errors: " << ostats.oerrors << std::endl;
        std::cout << "Transmit data rate (mbps): " << tx_data_rate << std::endl;
        std::cout << std::fixed << std::setprecision(1) << "Transmit packet rate (pps): " << tx_packet_rate << std::endl;
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << std::endl;
    }
}

void cleanup(const std::string input_port, const uint16_t input_port_id, const uint16_t output_port_id, const uint16_t num_rx_queues)
{
    rte_eth_dev_stop(input_port_id);
    rte_eth_dev_close(input_port_id);

    if (input_port_id != output_port_id) {
        rte_eth_dev_stop(output_port_id);
        rte_eth_dev_close(output_port_id);
    }

    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        const std::string memzone_name = input_port + "_" + std::to_string(i);
        rte_memzone *const memzone = rte_memzone_lookup(memzone_name.c_str());
        if (memzone) {
            rte_memzone_free(memzone);
        } else {
            std::cerr << "Unable to lookup memzone while doing cleanup: " << memzone_name;
        }

        const std::string mempool_name = input_port + "_" + std::to_string(i);
        rte_mempool *const mempool = rte_mempool_lookup(mempool_name.c_str());
        if (mempool) {
            rte_mempool_free(mempool);
        } else {
            std::cerr << "Unable to lookup mempool while doing cleanup: " << mempool_name;
        }
    }

    rte_eal_cleanup();
}

void check_supported_packet_types(const uint16_t port_id)
{
	int nb_ptypes = rte_eth_dev_get_supported_ptypes(port_id, RTE_PTYPE_ALL_MASK, NULL, 0);
	if (nb_ptypes < 0) {
		std::cerr << "Unable to check supported packet types. Port id: " << port_id << " Return code: " << nb_ptypes << std::endl;
		return;
	}

    if (nb_ptypes == 0) {
        std::cerr << "No packet type supported. Port Id: " << port_id << std::endl;
        return;
    }

	uint32_t ptypes[nb_ptypes];
	nb_ptypes = rte_eth_dev_get_supported_ptypes(port_id, RTE_PTYPE_ALL_MASK, ptypes, nb_ptypes);
	    
    std::cout << "Port id: " << port_id << " supported packet types: " << std::endl;
	for (int i = 0; i < nb_ptypes; ++i) {
        char ptype_name_buffer[100] = {0};
        int ret_val = rte_get_ptype_name(ptypes[i], ptype_name_buffer, sizeof(ptype_name_buffer));
        if (ret_val < 0) {
            std::cerr << "Unable to get packet type name. Packet type: " << ptypes[i] << std::endl;
            continue;
        }

        std::cout << " " << ptype_name_buffer << std::endl;
	}
    std::cout << std::endl;

	return;
}

bool configure_eth_port(const std::string port, 
                        const uint16_t port_id, 
                        const uint16_t num_rx_queues, 
                        const uint16_t num_tx_queues, 
                        const uint16_t num_rx_queues_descriptors, 
                        const uint16_t num_tx_queues_descriptors) {
    
    // Fetch the device (port) information.
    rte_eth_dev_info dev_info {};
    int return_val = rte_eth_dev_info_get(port_id, &dev_info);
    if (return_val != 0) {
        printf("Unable to get device info (port %u). Return code: %d", port_id, return_val);
        return false;
    }

    if (num_rx_queues > dev_info.max_rx_queues) {
        std::cerr << "Configured Rx queues: " << num_rx_queues << " exceeds the available device Rx queues: " 
                  << dev_info.max_rx_queues << std::endl;
        return false;
    }

    if (num_tx_queues > dev_info.max_tx_queues) {
        std::cerr << "Configured Tx queues: " << num_tx_queues << " exceeds the available device Tx queues: " 
                  << dev_info.max_tx_queues << std::endl;
        return false;
    }

    if ((num_rx_queues_descriptors > dev_info.rx_desc_lim.nb_max) || 
        (num_rx_queues_descriptors < dev_info.rx_desc_lim.nb_min)) {
	    std::cerr << "Configured Rx descriptors count: " << num_rx_queues_descriptors << " is not in the valid range." << std::endl;
	    std::cout << "Valid range: [" << dev_info.rx_desc_lim.nb_min << " - " << dev_info.rx_desc_lim.nb_max << "]" << std::endl;
	    std::cout << "Descriptors count align: " << dev_info.rx_desc_lim.nb_align << std::endl;
	    return false;
    }

    if ((num_tx_queues_descriptors > dev_info.tx_desc_lim.nb_max) || 
        (num_tx_queues_descriptors < dev_info.tx_desc_lim.nb_min)) {
	    std::cerr << "Configured Tx descriptors count: " << num_tx_queues_descriptors << " is not in the valid range." << std::endl;
	    std::cout << "Valid range: [" << dev_info.tx_desc_lim.nb_min << " - " << dev_info.tx_desc_lim.nb_max << "]" << std::endl;
	    std::cout << "Descriptors count align: " << dev_info.tx_desc_lim.nb_align << std::endl;
	    return false;
    }

    rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_NONE
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE
        }
    };

    if (num_rx_queues > 1) {
        // Enabling receive side scaling (RSS) as more than one Rx queues are enabled.
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

        // Using the default hash function by setting the rss_key to null.
        port_conf.rx_adv_conf.rss_conf.rss_key = nullptr;

        // Setting the default RSS hash key len.
        port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;

        // Setting packet types on which RSS hash function will be applied.
        // All the packets other then the mentioned type will be always be queued to queue 0.
        // Hash value supported by XL710-QDA2 adapter: 0x7ef8. According to this value the supported 
        // hash types are as below:
        //  - RTE_ETH_RSS_FRAG_IPV4          RTE_BIT64(3)
        //  - RTE_ETH_RSS_NONFRAG_IPV4_TCP   RTE_BIT64(4)
        //  - RTE_ETH_RSS_NONFRAG_IPV4_UDP   RTE_BIT64(5)
        //  - RTE_ETH_RSS_NONFRAG_IPV4_SCTP  RTE_BIT64(6)
        //  - RTE_ETH_RSS_NONFRAG_IPV4_OTHER RTE_BIT64(7)
        //  - RTE_ETH_RSS_FRAG_IPV6          RTE_BIT64(9)
        //  - RTE_ETH_RSS_NONFRAG_IPV6_TCP   RTE_BIT64(10)
        //  - RTE_ETH_RSS_NONFRAG_IPV6_UDP   RTE_BIT64(11)
        //  - RTE_ETH_RSS_NONFRAG_IPV6_SCTP  RTE_BIT64(12)
        //  - RTE_ETH_RSS_NONFRAG_IPV6_OTHER RTE_BIT64(13)
        //  - RTE_ETH_RSS_L2_PAYLOAD         RTE_BIT64(14)
        port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_UDP;
    }

    // Configure the port.
    if ((return_val = rte_eth_dev_configure(port_id, num_rx_queues, num_tx_queues, &port_conf)) != 0) {
        std::cerr << "Unable to configure port. port Id: " << port_id << " Return code: "  << return_val << std::endl;
        return false;
    }

    const int port_socket_id = rte_eth_dev_socket_id(port_id);
    const int core_socket_id = rte_socket_id();

    if ((port_socket_id != SOCKET_ID_ANY) && port_socket_id != core_socket_id) {
        printf("Port socket id: %d is not same as core socket id: %d. Performance will be impacted. Select the logical core which has same socket id as of port socket id \n");
        return false;
    }

    // Configure the rx queue(s) of the port.
    for (uint16_t i = 0; i < num_rx_queues; i++) {
        const std::string mempool_name = port + "_" + std::to_string(i);
        rte_mempool *const mempool = rte_mempool_lookup(mempool_name.c_str());
        if (!mempool) {
            std::cerr << "Unable to lookup mempool: " << mempool << std::endl;
            return false;
        }

        return_val = rte_eth_rx_queue_setup(port_id, i, num_rx_queues_descriptors, core_socket_id, nullptr, mempool);
        if (return_val < 0) {
            std::cerr << "Unable to setup Rx queue: " << i << " Port Id: " << port_id << " Return code: " << return_val << std::endl;
            return false;
        }

        std::cout << "Port Id: " << port_id << " Rx Queue: " << i << " setup successful. Port Socket Id: "
                  << port_socket_id << " Core Socket Id: " << core_socket_id << std::endl;
    }

    // Configure the tx queue(s) of the port.
    for (uint16_t i = 0; i < num_tx_queues; i++) {
        return_val = rte_eth_tx_queue_setup(port_id, i, num_tx_queues_descriptors, core_socket_id, nullptr);
        if (return_val < 0) {
            std::cerr << "Unable to setup Tx queue: " << i << " Port Id: " << port_id << " Return code: " << return_val << std::endl;
            return false;
        }

        std::cout << "Port Id: " << port_id << " Tx Queue: " << i << " setup successful. Port Socket Id: "
                  << port_socket_id << " Core Socket Id: " << core_socket_id << std::endl;
    }

    // Enable promiscuous mode on the port. Not all the DPDK drivers provide the functionality to enable promiscuous mode. So we are going to 
    // ignore the result if the API fails.
    return_val = rte_eth_promiscuous_enable(port_id);
    if (return_val < 0) {
        std::cout << "Warning: Unable to set the promiscuous mode for port Id: " << port_id << " Return code: " << return_val << " Ignoring ... " << std::endl;
    }

    // All the configuration is done. Finally starting the port (ethernet interface) so that we can start 
    // receiving/transmitting the packets.
    return_val = rte_eth_dev_start(port_id);
    if (return_val < 0) {
        std::cout << "Unable to start port. Port Id: " << port_id << " Return code: " << return_val << std::endl;
        return false;
    }

    std::cout << "Port configuration successful. Port Id: " << port_id << std::endl;
    return true;
}

void usage()
{
    std::cout << "./high_performance_firewall -l <logical_cores> -n 4 [-b <SKIP_PORT_PCI_ADDRESS>] -- --input-port <PCI_ADDRESS> --output-port <PCI_ADDRESS> --num-rx-queues <NUMBER_OF_RX_QUEUES>" << std::endl;
}

int main(int argc, char **argv)
{
    std::cout << "Starting firewall ... " << std::endl;

    // Setting up signals to catch TERM and INT signal.
    sigaction action {};
    memset(&action, 0, sizeof(sigaction));
    action.sa_handler = terminate_signal_handler;
    sigaction(SIGTERM, &action, nullptr);
    memset(&action, 0, sizeof(sigaction));
    action.sa_handler = interrupt_signal_handler;
    sigaction(SIGINT, &action, nullptr);

    // Initialize the DPDK EAL (Environment abstraction layer).
    int32_t return_val = rte_eal_init(argc, argv);
    if (return_val < 0) {
        std::cerr << "Unable to initialize DPDK EAL (Environment Abstraction Layer). Error code: " << rte_errno << std::endl;
        exit(1);
    }

    argc -= return_val;
    argv += return_val;

    std::string input_port, output_port, number_of_rx_queues;
    for (uint16_t i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--input-port") == 0) {
            if ((i + 1) < argc) {
                input_port = argv[i + 1];
            } else {
                break;
            }
        }

        if (strcmp(argv[i], "--output-port") == 0) {
            if ((i + 1) < argc) {
                output_port = argv[i + 1];
            } else {
                break;
            }
        }

        if (strcmp(argv[i], "--num-rx-queues") == 0) {
            if ((i + 1) < argc) {
                number_of_rx_queues = argv[i + 1];
            } else {
                break;
            }
        }
    }

    if (input_port.empty()) {
        std::cerr << "Input port not specified. " << std::endl;
        usage();
        exit(1);
    }

    if (output_port.empty()) {
        std::cerr << "Output port not specified. " << std::endl;
        usage();
        exit(1);
    }

    if (number_of_rx_queues.empty()) {
        std::cerr << "Number of rx queues not specified. " << std::endl;
        usage();
        exit(1);
    }

    // Check whether the input port is detected by the application.
    uint16_t input_port_id = std::numeric_limits<decltype(input_port_id)>::max();
    if (rte_eth_dev_get_port_by_name(input_port.c_str(), &input_port_id)) {
        std::cerr << "Unable to get port id against port: " << input_port << std::endl;
        rte_eal_cleanup();
        exit(1);
    }
    std::cout << "Input port: " << input_port << " detected by the application. Input port id: " << input_port_id << std::endl;

    // Check whether the output port is detected by the application.
    uint16_t output_port_id = std::numeric_limits<decltype(output_port_id)>::max();
    if (rte_eth_dev_get_port_by_name(output_port.c_str(), &output_port_id)) {
        std::cerr << "Unable to get port id against port: " << output_port << std::endl;
        rte_eal_cleanup();
        exit(1);
    }
    std::cout << "Output port: " << output_port << " detected by the application. Output port id: " << output_port_id << std::endl;

    uint16_t num_rx_queues {0};
    try {
        num_rx_queues = std::stoi(number_of_rx_queues.c_str());
        if (num_rx_queues == 0) {
            std::cerr << "Atleast one rx queue must be specified. " << std::endl;
            rte_eal_cleanup();
            exit(1);
        }
    }
    catch(const std::exception& e) {
        std::cerr << "Invalid number of rx queues specified: " << e.what() << std::endl;
        rte_eal_cleanup();
        exit(1);
    }
    
    /*std::list<std::pair<uint32_t, uint32_t>> port_and_queue_info_list;
    port_and_queue_info_list.push_back(std::make_pair(input_port_id, num_rx_queues));
    auto &rule_mngr = rule_manager::get_instance();
    if (!rule_mngr.initialize(port_and_queue_info_list)) {
        rule_mngr.cleanup();
        rte_eal_cleanup();
        exit(1);
    }*/

    // Detecting the logical cores (CPUs) ids passed to this DPDK application. 
    uint16_t i = 0;
    std::vector<uint16_t> logical_cores;
    std::cout << "Logical cores ids (CPU ids): ";
    RTE_LCORE_FOREACH(i) {
        logical_cores.push_back(i);
        std::cout << i << " ";
    }
    std::cout << std::endl;

    // We need sufficient logical cores to run:
    // - main thread, packet receiving thread(s).
    const uint16_t num_required_logical_cores = 1 + num_rx_queues;
    if (logical_cores.size() != num_required_logical_cores) {
        std::cerr << "Insufficient count of logical cores are provided. Required logical cores count: " << num_required_logical_cores << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    // Creating memory pool(s) and shared memory zones against each receive queue of the input port.
    std::vector<PacketReadingThreadStatistics *> packet_reading_thread_statistics(num_rx_queues);    
    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        const std::string mempool_name = input_port + "_" + std::to_string(i);
        rte_mempool *const mempool = rte_pktmbuf_pool_create(mempool_name.c_str(),
                                                             MEMORY_POOL_SIZE,
                                                             512,
                                                             0,
                                                             RTE_MBUF_DEFAULT_BUF_SIZE,
                                                             rte_socket_id());
        if (!mempool) {
            std::cerr << "Unable to create memory pool: " << mempool_name << std::endl;
            cleanup(input_port, input_port_id, output_port_id, num_rx_queues);
            exit(1);
        }

        const std::string memzone_name = input_port + "_" + std::to_string(i);
        rte_memzone *const memzone = rte_memzone_reserve(memzone_name.c_str(),
                                                         sizeof(PacketReadingThreadStatistics),
                                                         rte_socket_id(),
                                                         RTE_MEMZONE_SIZE_HINT_ONLY);
        if (!memzone) {
            std::cerr << "Unable to create shared memory zone: " << memzone_name << std::endl;
            cleanup(input_port, input_port_id, output_port_id, num_rx_queues);
            exit(1);
        }

        packet_reading_thread_statistics[i] = new (memzone->addr) PacketReadingThreadStatistics;
    }

    // Configure the input/output ethernet port.
    if (!configure_eth_port(input_port_id, num_rx_queues, ((input_port_id == output_port_id) ? num_rx_queues : 0), NUM_QUEUE_RX_DESCRIPTORS, NUM_QUEUE_TX_DESCRIPTORS)) {
        cleanup(input_port, input_port_id, output_port_id, num_rx_queues);
        exit(1);
    }

    if (input_port_id != output_port_id) {
        // Configure the output ethernet port. (The tx queues of output port must be same as rx queues of input port).
        if (!configure_eth_port(output_port_id, 0, num_rx_queues, NUM_QUEUE_RX_DESCRIPTORS, NUM_QUEUE_TX_DESCRIPTORS, memory_pools)) {
            cleanup(input_port, input_port_id, output_port_id, num_rx_queues);
            exit(1);
        }
    }

    // Checking the packet types parsing supported by the input ethernet port.
    check_supported_packet_types(input_port_id);

    uint16_t lcore_idx = 1;
    // Initiating the packet reading and processing routines on the logical cores.
    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        auto packetReadingThreadParams = new PacketReadingThreadParams;
        packetReadingThreadParams->input_port = input_port;
        packetReadingThreadParams->input_port_id = input_port_id;
        packetReadingThreadParams->output_port_id = output_port_id;
        packetReadingThreadParams->queue_id = i;

        if ((return_val = rte_eal_remote_launch(read_and_process_packets_from_port, reinterpret_cast<void *>(packetReadingThreadParams), logical_cores[lcore_idx])) != 0) {
            std::cerr << "Unable to launch packet reading routine on the logical core: %d. Return code: %d" << logical_cores[lcore_idx] << return_val << std::endl;
            cleanup(input_port, input_port_id, output_port_id, num_rx_queues);
            exit(1);
        }

        lcore_idx++;
    }

    /*if ((return_val = rte_eal_remote_launch(manage_acl_rules, nullptr, logicalCores[lcoreIdx])) != 0) {
        std::cerr << "Unable to launch rule manager routine on the logical core: %d. Return code: %d" << logicalCores[lcoreIdx] << return_val << std::endl;
        cleanup(input_port_id, output_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }
    lcoreIdx++;*/

    while (!exit_application.load(std::memory_order_relaxed)) {
        std::string command;
        std::cout << "Enter command: ";
        std::getline(std::cin, command);

        if (command.empty()) {
            continue;
        }

        if (command == "show_statistics") {
            std::chrono::time_point<std::chrono::system_clock> t1 = std::chrono::system_clock::now();
            stop_printing_statistics.store(false, std::memory_order_relaxed);
            while (!stop_printing_statistics.load(std::memory_order_relaxed)) {
                std::chrono::time_point<std::chrono::system_clock> t2 = std::chrono::system_clock::now();
                const auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

                if (diff.count() >= STATISTICS_DISPLAY_INTERVAL_MSEC) {
                    print_statistics(input_port, input_port_id, output_port, output_port_id, num_rx_queues, packet_reading_thread_statistics);
                    t1 = t2;
                }

                using namespace std::literals;
                std::this_thread::sleep_for(50ms);
            }
        } else if (command == "exit") {
            terminate_signal_handler(0);
        } else {
            std::cout << "Invalid command. Valid commands are:                         " << std::endl;
            std::cout << "  show_statistics       [Print the application statistics]   " << std::endl;
            std::cout << "  exit                  [Exits the application]              " << std::endl;
        }
    }

    std::cout << "Exiting application ... " << std::endl;

    // Now we will wait for all the lcores (except main lcore = 0) to finish before we exit the application.
    for (uint16_t i = 1; i < logical_cores.size(); ++i) {
        std::cout << "Waiting for logical core " << logical_cores[i] << " to join. " << std::endl;
        rte_eal_wait_lcore(logical_cores[i]);
    }

    cleanup(input_port, input_port_id, output_port_id, num_rx_queues);
    return 0;
}

