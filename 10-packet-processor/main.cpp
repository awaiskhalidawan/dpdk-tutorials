// MIT License
// 
// Copyright (c) 2024 Muhammad Awais Khalid
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
#include <thread>
#include <csignal>
#include <vector>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <atomic>
#include <iomanip>
#include <cstring>
#include <array>
#include <utility>
#include <packet_dumper.hpp>
#include <rule_manager.hpp>

constexpr uint16_t NIC_STATISTICS_INTERVAL_MSEC       = 1000;        // 1 seconds.
constexpr uint32_t MEMORY_POOL_SIZE                   = 131071;      // Size of memory pool.
constexpr uint32_t RING_BUFFER_SIZE                   = 65536;       // Size of ring buffer.
constexpr uint32_t RX_BURST_SIZE                      = 32;          // Rx burst size.
constexpr uint32_t MAX_PACKET_PROCESSING_WORKER_COUNT = 4;           // Max packet processing worker count.
constexpr uint32_t NUM_QUEUE_RX_DESCRIPTORS           = 1024;        // Number of descriptors configured for Rx queue.
constexpr uint32_t MAX_ETH_RX_QUEUES                  = 4;           // Max number of Rx queues configured for ethernet port.
constexpr uint32_t MAX_PCAP_DUMP_FILE_SIZE_MB         = 200;         // Maximum size of pcap dump file in MB.
constexpr uint32_t DATA_PLANE_ACL_RULES_CHECK_TIME_MS   = 1000;	     // Data plane acl rules check interval in ms.
constexpr uint32_t RULE_MANAGER_ACL_RULES_CHECK_TIME_MS = 1000;	     // Rule manager acl rules check interval in ms.
static const std::string MEMORY_POOL_NAME_PREFIX      = "mempool_";       // Prefix name of memory pool.
static const std::string RING_BUFFER_NAME_PREFIX      = "ring_buffer_";   // Ring buffer name prefix.

static std::atomic<bool> exit_indicator = false;

struct PacketReadingThreadParams 
{
    uint16_t port_id {std::numeric_limits<decltype(port_id)>::max()};
    uint16_t queue_id {std::numeric_limits<decltype(queue_id)>::max()};
    uint16_t num_packet_processing_workers {0};
    int32_t timestamp_dynfield_offset {-1};
};

struct StatisticsThreadParams
{
    uint16_t port_id {std::numeric_limits<decltype(port_id)>::max()};
    uint16_t num_rx_queues {0};
    uint16_t num_packet_processing_workers {0};
};

struct PacketProcessingThreadParams 
{
    uint16_t queue_id {std::numeric_limits<decltype(queue_id)>::max()};
    uint16_t worker_id {std::numeric_limits<decltype(worker_id)>::max()};
    int32_t timestamp_dynfield_offset {-1};
};

static const struct rte_mbuf_dynfield timestamp_dynfield_descriptor = {
    .name = "dynfield_timestamp",
    .size = sizeof(uint64_t),
    .align = __alignof__(uint64_t),
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
    std::atomic<uint64_t> worker_tx_packets[MAX_PACKET_PROCESSING_WORKER_COUNT] {0};
    std::atomic<uint64_t> worker_tx_drop_packets[MAX_PACKET_PROCESSING_WORKER_COUNT] {0};
};

static PacketReadingThreadStatistics packet_reading_thread_statistics[MAX_ETH_RX_QUEUES];

static rte_mempool **memory_pools {nullptr};

static rte_ring ***ring_buffers {nullptr}; 

static rte_flow *flow {nullptr};

void terminate(int signal) 
{
    exit_indicator.store(true, std::memory_order_relaxed);
    auto &rule_mgr = rule_manager::get_instance();
    rule_mgr.stop();
}

int process_packets(void *param) 
{
    if (!param) {
        return -1;
    }

    PacketProcessingThreadParams *params = reinterpret_cast<PacketProcessingThreadParams *>(param);
    const uint16_t queue_id = params->queue_id;
    const uint16_t worker_id = params->worker_id;
    const int32_t timestamp_dynfield_offset = params->timestamp_dynfield_offset;

    printf("Starting packet processing routine. Queue Id: %u  Worker Id: %u  Logical core id (CPU Id): %d \n", queue_id, worker_id, rte_lcore_id());

    const std::string ring_buffer_name = RING_BUFFER_NAME_PREFIX + std::to_string(queue_id) + "_" + std::to_string(worker_id);

    rte_ring* ring_buffer = rte_ring_lookup(ring_buffer_name.c_str());
    if (!ring_buffer) {
        std::cerr << "Unable to look up ring buffer: " << ring_buffer_name << std::endl;
        return -1;
    }

    // Create a packet dumper instance.
    auto pkt_dumper = std::make_unique<packet_dumper>("/tmp", MAX_PCAP_DUMP_FILE_SIZE_MB, timestamp_dynfield_offset);

    rte_mbuf *rx_packets[RX_BURST_SIZE] = {nullptr};
    uint64_t rx_count = 0;

    auto tp1 = std::chrono::high_resolution_clock::now();

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        auto tp2 = std::chrono::high_resolution_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(tp2 - tp1).count() >= PACKET_DUMP_FILE_FLUSH_TIMEOUT_MS) {
            tp1 = tp2;
            pkt_dumper->flush();
        }

        // Read the packets from ring buffer in bursts.
        rx_count = rte_ring_dequeue_burst(ring_buffer, reinterpret_cast<void **>(rx_packets), RX_BURST_SIZE, nullptr);
        if (rx_count == 0) {
            // No packets found. Check again.
            continue;
        }

        // Write the packets to PCAP file.
        for (uint16_t i = 0; i < rx_count; ++i) {
            pkt_dumper->dump(rx_packets[i]);
        }

        rte_pktmbuf_free_bulk(rx_packets, rx_count);
    }
    
    std::cout << "Exiting packet processing routine. " << std::endl;
    delete reinterpret_cast<PacketProcessingThreadParams *>(param);
    return 0;
}

int manage_acl_rules(void *param)
{
    auto &rule_mgr = rule_manager::get_instance();
    rule_mgr.check_and_update_acl_contexts();
    return 0;
}

int read_packets(void *param)
{
    if (!param) {
        return -1;
    }

    PacketReadingThreadParams *params = reinterpret_cast<PacketReadingThreadParams *>(param);
    const uint16_t port_id = params->port_id;
    const uint16_t queue_id = params->queue_id;
    const uint16_t num_packet_processing_workers = params->num_packet_processing_workers;
    const int32_t timestamp_dynfield_offset = params->timestamp_dynfield_offset;

    auto &rule_manager = rule_manager::get_instance();
    auto ipv4_acl_ctx = rule_manager.get_data_plane_acl_ctx_ipv4(port_id, queue_id);

    if (!ipv4_acl_ctx) {
        std::cerr << "ACL context ipv4 is not valid. Cannot continue. " << std::endl;
        return -1;
    }

    printf("Starting packet reading routine. Port Id: %u  Queue Id: %u  Logical core id (CPU Id): %d  Packet processing workers count: %u \n", 
            port_id, queue_id, rte_lcore_id(), num_packet_processing_workers);

    rte_ring** ring_buffers = new rte_ring* [num_packet_processing_workers];
    if (!ring_buffers) {
        std::cerr << "Unable to allocate memory for ring buffers. " << std::endl;
        return -1;
    }

    for (uint16_t i = 0; i < num_packet_processing_workers; ++i) {
        const std::string ring_buffer_name = RING_BUFFER_NAME_PREFIX + std::to_string(queue_id) + "_" + std::to_string(i);
        ring_buffers[i] = rte_ring_lookup(ring_buffer_name.c_str());
        if (!ring_buffers[i]) {
            std::cerr << "Unable to lookup ring buffer: " << ring_buffer_name << std::endl;
            return -1;
        }
    }

    rte_mbuf *rx_packets[RX_BURST_SIZE] = {nullptr};
    rte_mbuf *ipv4_rx_packets[RX_BURST_SIZE] = {nullptr};
    rte_mbuf *ipv6_rx_packets[RX_BURST_SIZE] = {nullptr};
    uint64_t rx_count = 0;
    uint64_t ring_enqueue_count = 0;
    uint16_t ipv4_rx_packet_count {0};
    uint16_t ipv6_rx_packet_count {0};
    const uint8_t *ipv4_acl_inputs[RX_BURST_SIZE] = {nullptr};
    const uint8_t *ipv6_acl_inputs[RX_BURST_SIZE] = {nullptr};
    uint32_t ipv4_acl_results[RX_BURST_SIZE * DEFAULT_MAX_CATEGORIES] = {0};
    uint32_t ipv6_acl_results[RX_BURST_SIZE * DEFAULT_MAX_CATEGORIES] = {0};
    uint16_t unknown_type_rx_packet_count {0};
    uint16_t ipv4_classified_packet_count {0};
    uint16_t ipv6_classified_packet_count {0};
    timespec ts {0};
    auto tp0 = std::chrono::high_resolution_clock::now();

    // Now we go into a loop to continously check the port (ethernet interface) for any incoming packets. This process is called polling.
    while (!exit_indicator.load(std::memory_order_relaxed)) {
	    // Check for ACL context updates periodically.
	    auto tp1 = std::chrono::high_resolution_clock::now();
	    if (std::chrono::duration_cast<std::chrono::milliseconds>(tp1 - tp0).count() >= DATA_PLANE_ACL_RULES_CHECK_TIME_MS) {
	        ipv4_acl_ctx = rule_manager.get_data_plane_acl_ctx_ipv4(port_id, queue_id);
	        tp0 = tp1;
	    }
	    
	    // Read the packets from interface in bursts.
        rx_count = rte_eth_rx_burst(port_id, queue_id, rx_packets, RX_BURST_SIZE);

        if (rx_count == 0) {
            // No packets found. Check again.
            continue;
        }
        
        // Timestamp the packets.
        /*clock_gettime(CLOCK_REALTIME, &ts);
        const uint64_t timestamp = (ts.tv_sec * 1000000000) + ts.tv_nsec;
        for (uint16_t i = 0; i < rx_count; ++i) {
            *(RTE_MBUF_DYNFIELD(rx_packets[i], timestamp_dynfield_offset, uint64_t *)) = timestamp;
        }*/

        // Update the statistics.
        ATOMIC_INCREMENT_RELAXED(packet_reading_thread_statistics[queue_id].rx_packets, rx_count);

        ipv4_rx_packet_count = ipv6_rx_packet_count = unknown_type_rx_packet_count = 0;
	    ipv4_classified_packet_count = ipv6_classified_packet_count = 0;

        for (uint16_t i = 0; i < rx_count; ++i) {
            if (rx_packets[i]->packet_type & RTE_PTYPE_L3_IPV4 == RTE_PTYPE_L3_IPV4) {
                ipv4_rx_packets[ipv4_rx_packet_count++] = std::exchange(rx_packets[i], nullptr);
            } else if (rx_packets[i]->packet_type & RTE_PTYPE_L3_IPV6 == RTE_PTYPE_L3_IPV6) {
                ipv6_rx_packets[ipv6_rx_packet_count++] = std::exchange(rx_packets[i], nullptr);
            } else {
                ++unknown_type_rx_packet_count;
            }
        }

        ATOMIC_INCREMENT_RELAXED(packet_reading_thread_statistics[queue_id].unknown_type_rx_packets, unknown_type_rx_packet_count);
	    ATOMIC_INCREMENT_RELAXED(packet_reading_thread_statistics[queue_id].ipv4_rx_packets, ipv4_rx_packet_count);
        ATOMIC_INCREMENT_RELAXED(packet_reading_thread_statistics[queue_id].ipv6_rx_packets, ipv6_rx_packet_count);
	
	    // Free the received packets which are not identified.
        rte_pktmbuf_free_bulk(rx_packets, rx_count);

        for (uint16_t i = 0; i < ipv4_rx_packet_count; ++i) {
            ipv4_acl_inputs[i] = rte_pktmbuf_mtod(ipv4_rx_packets[i], uint8_t *) + sizeof(rte_ether_hdr);
        }

        int return_val = rte_acl_classify(ipv4_acl_ctx, ipv4_acl_inputs, ipv4_acl_results, ipv4_rx_packet_count, DEFAULT_MAX_CATEGORIES);
        if (likely(!return_val)) {
	        for (uint16_t i = 0; i < ipv4_rx_packet_count; ++i) {
	            if (ipv4_acl_results[i]) {
		        ++ipv4_classified_packet_count;
	            }
	        }
	        ATOMIC_INCREMENT_RELAXED(packet_reading_thread_statistics[queue_id].ipv4_classified_packets, ipv4_classified_packet_count);
	    } else {
	        ATOMIC_INCREMENT_RELAXED(packet_reading_thread_statistics[queue_id].acl_classify_failures, 1);
	    }

	    rte_pktmbuf_free_bulk(ipv4_rx_packets, ipv4_rx_packet_count);
        rte_pktmbuf_free_bulk(ipv6_rx_packets, ipv6_rx_packet_count);

        /*for (uint16_t i = 0; i < num_packet_processing_workers; ++i) {
            ring_enqueue_count = rte_ring_enqueue_burst(ring_buffers[i], reinterpret_cast<void *const *>(rx_packets), rx_count, nullptr);
            
            // Update the statistics.
            ATOMIC_INCREAMENT_RELAXED(packet_reading_thread_statistics[queue_id].worker_tx_packets[i], ring_enqueue_count);

            // Free up the packets in bulk which are unable to enqueued on the ring buffer.
            if (ring_enqueue_count < rx_count) {
                rte_pktmbuf_free_bulk(&rx_packets[ring_enqueue_count], (rx_count - ring_enqueue_count));
 
                // Update the statistics.
                ATOMIC_INCREAMENT_RELAXED(packet_reading_thread_statistics[queue_id].worker_tx_drop_packets[i], (rx_count - ring_enqueue_count));
            }
        }*/
    }
    
    std::cout << "Exiting packet reading routine. " << std::endl;
    delete reinterpret_cast<PacketReadingThreadParams *>(param);
    return 0;
}

int get_and_print_nic_statistics(void *param)
{
    if (!param) {
        return -1;
    }

    int return_val = -1;
    auto statisticsThreadParams = reinterpret_cast<StatisticsThreadParams *>(param);
    const uint16_t port_id = statisticsThreadParams->port_id;
    const uint16_t num_rx_queues = statisticsThreadParams->num_rx_queues;
    const uint16_t num_packet_processing_workers = statisticsThreadParams->num_packet_processing_workers;

    std::chrono::time_point<std::chrono::system_clock> t1 = std::chrono::system_clock::now();
    rte_eth_stats stats = {0};
    uint64_t last_rx_bytes = 0;
    uint64_t last_tx_bytes = 0;
    uint64_t last_rx_packets = 0;
    uint64_t last_tx_packets = 0;

    std::cout << "Starting nic statistics routine on logical core: " << rte_lcore_id() << std::endl;    

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        std::chrono::time_point<std::chrono::system_clock> t2 = std::chrono::system_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

        if (diff.count() >= NIC_STATISTICS_INTERVAL_MSEC) {
            t1 = t2;
            std::cout << "\033[2J\033[1;1H";
            if ((return_val = rte_eth_stats_get(port_id, &stats) == 0)) {
                auto now = std::chrono::system_clock::now();
                auto in_time_t = std::chrono::system_clock::to_time_t(now);

                const double rx_packet_rate = (static_cast<double>(stats.ipackets - last_rx_packets) / (static_cast<double>(diff.count()) / 1000.0));
                last_rx_packets = stats.ipackets;
                const double tx_packet_rate = (static_cast<double>(stats.opackets - last_tx_packets) / (static_cast<double>(diff.count()) / 1000.0));
                last_tx_packets = stats.opackets;

                const double rx_data_rate = (static_cast<double>((stats.ibytes - last_rx_bytes) * 8) / (static_cast<double>(diff.count()) / 1000.0)) / (1024.0 * 1024.0);
                last_rx_bytes = stats.ibytes;
                const double tx_data_rate = (static_cast<double>((stats.obytes - last_tx_bytes) * 8) / (static_cast<double>(diff.count()) / 1000.0)) / (1024.0 * 1024.0);
                last_tx_bytes = stats.obytes;                

                std::cout << std::endl;
                std::cout << "Ethernet Port: " << port_id << " Statistics" << std::endl;
                std::cout << "----------------------------------------------" << std::endl;
                std::cout << "Statistics time: " << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X") << std::endl;
                std::cout << "Receive  packets: " << stats.ipackets << std::endl;
                std::cout << "Transmit packets: " << stats.opackets << std::endl;
                std::cout << "Receive  bytes: " << stats.ibytes << std::endl;
                std::cout << "Transmit bytes: " << stats.obytes << std::endl;
                std::cout << "Receive  errors: " << stats.ierrors << std::endl;
                std::cout << "Transmit errors: " << stats.oerrors << std::endl;
                std::cout << "Rx rx_nombuf: " << stats.rx_nombuf << std::endl;
                std::cout << std::endl;
                std::cout << "Receive  data rate (mbps): " << rx_data_rate << std::endl;
                std::cout << "Transmit data rate (mbps): " << tx_data_rate << std::endl;
                std::cout << std::fixed << std::setprecision(1) << "Receive  packet rate (pps): " << rx_packet_rate << std::endl;
                std::cout << std::fixed << std::setprecision(1) << "Transmit packet rate (pps): " << tx_packet_rate << std::endl;
                std::cout << "----------------------------------------------" << std::endl;
                std::cout << std::endl;
                
                std::cout << "Packet Reading Thread(s) Statistics" << std::endl;
                std::cout << "----------------------------------------------" << std::endl;
                for (uint16_t i = 0; i < num_rx_queues; ++i) {
                    std::cout << "Rx queue: " << i << std::endl;
                    std::cout << "     Rx packets: " << packet_reading_thread_statistics[i].rx_packets.load(std::memory_order_relaxed) << std::endl;
		    std::cout << "     Rx (ipv4) packets: " << packet_reading_thread_statistics[i].ipv4_rx_packets.load(std::memory_order_relaxed) << std::endl;
                    std::cout << "     Rx (ipv6) packets: " << packet_reading_thread_statistics[i].ipv6_rx_packets.load(std::memory_order_relaxed) << std::endl;
		    std::cout << "     Classified (ipv4) packets: " << packet_reading_thread_statistics[i].ipv4_classified_packets.load(std::memory_order_relaxed) << std::endl;
                    std::cout << "     Classified (ipv6) packets: " << packet_reading_thread_statistics[i].ipv6_classified_packets.load(std::memory_order_relaxed) << std::endl;
		    std::cout << "     ACL classify failures: " << packet_reading_thread_statistics[i].acl_classify_failures.load(std::memory_order_relaxed) << std::endl;
		    
		    std::cout << "     Worker Tx packets: [ ";
                    for (uint16_t j = 0; j < num_packet_processing_workers; ++j) {
                        std::cout << packet_reading_thread_statistics[i].worker_tx_packets[j].load(std::memory_order_relaxed);
                        std::cout << " ";
                    }
                    std::cout << "]" << std::endl;

                    std::cout << "     Worker Tx drop packets: [ ";
                    for (uint16_t j = 0; j < num_packet_processing_workers; ++j) {
                        std::cout << packet_reading_thread_statistics[i].worker_tx_drop_packets[j].load(std::memory_order_relaxed);
                        std::cout << " ";
                    }
                    std::cout << "]" << std::endl;
                    std::cout << std::endl;
                }
                std::cout << "----------------------------------------------" << std::endl;
            } else {
                std::cerr << "Unable to get ethernet device statistics. Port id: " << port_id << " Return value: " << return_val << std::endl;
            }
        }

        using namespace std::literals;
        std::this_thread::sleep_for(50ms);
    }

    delete statisticsThreadParams;
    return 0;
}

void cleanup(const uint16_t port_id, const uint16_t num_rx_queues, const uint16_t num_packet_processing_workers)
{
    if (flow) {
	rte_flow_error flow_error;
	rte_flow_destroy(port_id, flow, &flow_error);
    }

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (memory_pools) {
        for (uint16_t i = 0; i < num_rx_queues; ++i) {
            rte_mempool_free(memory_pools[i]);
            memory_pools[i] = nullptr;
        }

        delete[] memory_pools;
        memory_pools = nullptr;
    }

    if (ring_buffers) {
        for (uint16_t i = 0; i < num_rx_queues; ++i) {
            if (ring_buffers[i]) {                
                for (uint16_t j = 0; j < num_packet_processing_workers; ++j) {
                    if (ring_buffers[i][j]) {
                        rte_ring_free(ring_buffers[i][j]);
                        ring_buffers[i][j] = nullptr;
                    }
                }

                delete[] ring_buffers[i];
                ring_buffers[i] = nullptr;
            }
        }

        delete[] ring_buffers;
        ring_buffers = nullptr;
    }

    rte_eal_cleanup();
}

bool check_supported_packet_types(const int target_port_id)
{
	uint32_t mask = (RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK | RTE_PTYPE_TUNNEL_MASK);
	int nb_ptypes = rte_eth_dev_get_supported_ptypes(target_port_id, mask, NULL, 0);

	if (nb_ptypes <= 0) {
		std::cerr << "Unable to check supported packet types. Return code: " << nb_ptypes << std::endl;
		return false;
	}

	uint32_t ptypes[nb_ptypes];
	nb_ptypes = rte_eth_dev_get_supported_ptypes(target_port_id, mask, ptypes, nb_ptypes);
	
	for (int i = 0; i < nb_ptypes; ++i) {
		if (RTE_ETH_IS_IPV4_HDR(ptypes[i])) {
			std::cout << "Packet type L3_IPV4 supported. " << std::endl;
		}
		if (RTE_ETH_IS_IPV6_HDR(ptypes[i])) {
			std::cout << "Packet type L3_IPV6 supported. " << std::endl;
		}
		if ((ptypes[i] & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_ESP) {
			std::cout << "Packet type TUNNEL_ESP supported. " << std::endl;
		}
		if ((ptypes[i] & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP) {
			std::cout << "Packet type L4_UDP supported. " << std::endl;
		}
		if ((ptypes[i] & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {
			std::cout << "Packet type L4_TCP supported. " << std::endl;
		}
	}

	return true;
}

int main(int argc, char **argv)
{
    // Setting up signals to catch TERM and INT signal.
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = terminate;
    sigaction(SIGTERM, &action, nullptr);
    sigaction(SIGINT, &action, nullptr);

    std::cout << "Starting DPDK program ... " << std::endl;

    // Initializing the DPDK EAL (Environment Abstraction Layer). This is the first step of a DPDK program before we 
    // call any further DPDK API.
    // The arguments passed to this programs are passed to rte_eal_init() DPDK API. A user must pass DPDK EAL arguments
    // before the application arguments. The DPDK EAL arguments and application arguments must be separated by '--'.
    // For example: ./<dpdk_application> --lcores=0,1 -n 4 -- -s 1 -t 2. `--` will tell the rte_eal_init() that all the DPDK
    // EAL arguments are present before this.  
    // In the above example the DPDK EAL arguments are --lcores and -n. The user arguments are -s and -t. 
    // DPDK EAL argument `--lcores=0,1` means that there are two logical cores (CPUs) assigned to this DPDK application. The 
    // first logical core is 0 and second is 1. DPDK application will launch total_logical_cores worker threads in the application (including main)
    // So in the above example, the DPDK application has two logical cores (0,1). The main function will run on first logical core (0)
    // and an additional worker thread will be launched on the next logical core (1). A DPDK application sets the affinity of 
    // execution threads to specific logical cores to achieve performance.
    // DPDK EAL argument `-n 4` means that this DPDK application uses 4 memory channels. 
    // The details are DPDK EAL arguments is present at: https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html
    int32_t return_val = rte_eal_init(argc, argv);
    if (return_val < 0) 
    {
        std::cerr << "Unable to initialize DPDK EAL (Environment Abstraction Layer). Error code: " << rte_errno << std::endl;
        exit(1);
    }

    // rte_eal_init() DPDK API will return the number of DPDK EAL arguments processed. So we will subtract the number of DPDK EAL
    // arguments from the total arguments and point argv to the first user argument.
    // For example: ./<dpdk_application> --lcores=0 -n 4 -- -s 1 -t 2
    // rte_eal_init() will return 4. The total arguments passed to this program is 9. So after subtracting the actual user arguments 
    // is (9 - 4 = 5). Setting `argv` to point to the start of user argument which is `--`
    argc -= return_val;
    argv += return_val;

    // Application input parameters. (Will be passed from command line in the future.)
    const std::string target_port = "0000:00:08.0"; //"0000:04:00.1"; // 0000:00:08.0
    const uint16_t num_rx_queues = 1;
    const uint16_t num_tx_queues = 0;
    const uint16_t num_packet_processing_workers = 1;

    // Check whether the target port is detected by the application.
    uint16_t target_port_id = std::numeric_limits<decltype(target_port_id)>::max();
    if (rte_eth_dev_get_port_by_name(target_port.c_str(), &target_port_id)) {
        std::cerr << "Unable to get port id against port: " << target_port << std::endl;
        rte_eal_cleanup();
        exit(1);
    }
    std::cout << "Target port: " << target_port << " detected by the application. Target port id: " << target_port_id << std::endl;

    std::list<std::pair<uint32_t, uint32_t>> port_and_queue_info_list;
    port_and_queue_info_list.push_back(std::make_pair(target_port_id, num_rx_queues));
    auto &rule_mngr = rule_manager::get_instance();
    if (!rule_mngr.initialize(port_and_queue_info_list)) {
        rule_mngr.cleanup();
        rte_eal_cleanup();
        exit(1);
    }

    // Detecting the logical cores (CPUs) ids passed to this DPDK application. 
    uint16_t i = 0;
    std::vector<uint16_t> logicalCores;
    std::cout << "Logical cores ids (CPU ids): ";
    RTE_LCORE_FOREACH(i) {
        logicalCores.push_back(i);
        std::cout << i << " ";
    }
    std::cout << std::endl;

    if ((num_rx_queues == 0) || (num_rx_queues > MAX_ETH_RX_QUEUES)) {
        std::cerr << "Invalid number of Rx queues. Max Rx queues allowed: " << MAX_ETH_RX_QUEUES << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    if ((num_packet_processing_workers == 0) || (num_packet_processing_workers > MAX_PACKET_PROCESSING_WORKER_COUNT)) {
        std::cerr << "Invalid number of packet processing workers. Max workers allowed: " << MAX_PACKET_PROCESSING_WORKER_COUNT << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    // We need sufficient logical cores to run:
    // - main thread, rule manager thread, packet receiving thread(s) and packet processing thread(s).
    const uint16_t num_required_logical_cores = 1 + 1 + num_rx_queues + (num_rx_queues * num_packet_processing_workers);
    if (logicalCores.size() != num_required_logical_cores) {
        std::cerr << "Insufficient count of logical cores are provided. Required logical cores count: " << num_required_logical_cores << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    uint16_t port_ids[RTE_MAX_ETHPORTS] = {0};
    int16_t id = 0;
    int16_t total_port_count = 0;
    
    // Detecting the available ports (ethernet interfaces) in the system.
    RTE_ETH_FOREACH_DEV(id) {
        port_ids[total_port_count++] = id;
        if (total_port_count >= RTE_MAX_ETHPORTS)
        {
            std::cerr << "Total number of detected ports exceeds RTE_MAX_ETHPORTS. " << std::endl;
            rte_eal_cleanup();
            exit(1);
        }
    }

    if (total_port_count == 0) {
        std::cerr << "No ports detected in the system. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    std::cout << "Total ports detected: " << total_port_count << std::endl;

    // Register the mbuf dynamic field for packet timestamps.
    const int32_t timestamp_dynfield_offset = rte_mbuf_dynfield_register(&timestamp_dynfield_descriptor);
    if (timestamp_dynfield_offset < 0) {
        std::cerr << "Unable to register mbuf dynamic field for timestamp. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    std::cout << "Timestamp dynamic field registered. Offset: " << timestamp_dynfield_offset << std::endl;

    // Creating memory pool against each receive queue.
    memory_pools = new rte_mempool* [num_rx_queues];
    if (!memory_pools) {
        std::cerr << "Unable to allocate memory pool array. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        const std::string mempool_name = MEMORY_POOL_NAME_PREFIX + std::to_string(i);
        memory_pools[i] = rte_pktmbuf_pool_create(mempool_name.c_str(), MEMORY_POOL_SIZE, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (!memory_pools[i]) {
            std::cerr << "Unable to initialize memory pool: " << mempool_name << std::endl;
            cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
            exit(1);
        }
    }

    //Creating ring buffers for transfer of packets b/w packet reading and processing threads.
    ring_buffers = new rte_ring** [num_rx_queues];
    if (!ring_buffers) {
        std::cerr << "Unable to allocate memory for ring buffers ..." << std::endl;
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        ring_buffers[i] = new rte_ring* [num_packet_processing_workers];
        if (!ring_buffers[i]) {
            std::cerr << "Unable to allocate memory for ring buffers ..." << std::endl;
            cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
            exit(1);
        }

        for (uint16_t j = 0; j < num_packet_processing_workers; ++j) {
            const std::string ring_buffer_name = RING_BUFFER_NAME_PREFIX + std::to_string(i) + "_" + std::to_string(j);
            ring_buffers[i][j] = rte_ring_create(ring_buffer_name.c_str(), RING_BUFFER_SIZE, rte_socket_id(), (RING_F_SP_ENQ | RING_F_SC_DEQ));
            if (!ring_buffers[i][j]) {
                std::cerr << "Unable to create ring buffer: " << ring_buffer_name << std::endl;
                cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
                exit(1);
            }
        }
    }

    // Configuring the port (ethernet interface). An ethernet interface can have multiple receive queues and transmit queues. 
    // Currently we are setting up two receive queues and no transmit queue as we are not sending packets in this tutorial.
 
    // Hash value supported by XL710-QDA2 adapter: 0x7ef8. According to this value the supported hash types are as below:
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

    rte_eth_conf portConf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_NONE
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE
        }/*,
        .rx_adv_conf = {
            .rss_conf = {
            //.rss_key = nullptr,                         // Using the default hash function by setting the rss_key to null.
     	    //.rss_key_len = 40,
            .rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_UDP      // RSS hash function is only applied to non-fragmented IPv4 packets. 
                                                        // The IPv4 non-fragmented packets will be distributed among the receive 
                                                        // queues according to the calculated RSS hash. All the packets other then
                                                        // UDP IPv4 fragmented packets will be always be queued to queue 0. 
            }
        }*/
    };

    // We will fetch the device info to check how many receive queues are supported by our ethernet device.
    rte_eth_dev_info devInfo;
    return_val = rte_eth_dev_info_get(target_port_id, &devInfo);
    if (return_val != 0) {
        printf("Error occurred while getting device info (port %u). Return code: %d", target_port_id, return_val);
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    if (num_rx_queues > devInfo.max_rx_queues) {
        std::cerr << "Configured Rx queues: " << num_rx_queues << " exceeds the available device Rx queues: " 
                  << devInfo.max_rx_queues << std::endl;
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    // Configure the port (ethernet interface).
    if ((return_val = rte_eth_dev_configure(target_port_id, num_rx_queues, num_tx_queues, &portConf)) != 0) {
        std::cerr << "Unable to configure port. port Id: " << target_port_id << " Return code: "  << return_val << std::endl;
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    const int16_t portSocketId = rte_eth_dev_socket_id(target_port_id);
    const int16_t coreSocketId = rte_socket_id();

    // Configure the queue(s) of the port.
    for (uint16_t i = 0; i < num_rx_queues; i++) {
        return_val = rte_eth_rx_queue_setup(target_port_id, i, NUM_QUEUE_RX_DESCRIPTORS, ((portSocketId >= 0) ? portSocketId : coreSocketId), nullptr, 
                                            memory_pools[i]);
        
        if (return_val < 0) {
            std::cerr << "Unable to setup Rx queue: " << i << " Port Id: " << target_port_id << " Return code: " << return_val << std::endl;
            cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
            exit(1);
        }

        std::cout << "Port Id: " << target_port_id << " Rx Queue: " << i << " setup successful. Port Socket Id: "   
                  << portSocketId << " Core Socket Id: " << coreSocketId << std::endl;
    }

    // Enable promiscuous mode on the port. Not all the DPDK drivers provide the functionality to enable promiscuous mode. So we are going to 
    // ignore the result if the API fails.
    return_val = rte_eth_promiscuous_enable(target_port_id);
    if (return_val < 0) {
        std::cout << "Warning: Unable to set the promiscuous mode for port Id: " << target_port_id << " Return code: " << return_val << " Ignoring ... " << std::endl;
    }

    // All the configuration is done. Finally starting the port (ethernet interface) so that we can start receiving the packets.
    return_val = rte_eth_dev_start(target_port_id);
    if (return_val < 0) {
        std::cout << "Unable to start port. Port Id: " << target_port_id << " Return code: " << return_val << std::endl;
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    std::cout << "Port configuration successful. Port Id: " << target_port_id << std::endl;

    // Configure RTE flow.
    /*rte_flow_error flow_error;
    rte_flow_attr flow_attr = {0};
    flow_attr.ingress = 1;
    rte_flow_action flow_actions[2];
    rte_flow_item flow_patterns[3];

    std::array<uint8_t, 6> src_mac = {0x08, 0x00, 0x27, 0x95, 0xbd, 0xf1};
    std::array<uint8_t, 6> dst_mac = {0x08, 0x00, 0x27, 0x35, 0x14, 0xf1};
    
    rte_flow_item_eth eth_spec = {0};
    //std::memcpy(eth_spec.src.addr_bytes, src_mac.data(), sizeof(eth_spec.src.addr_bytes));
    //std::memcpy(eth_spec.dst.addr_bytes, dst_mac.data(), sizeof(eth_spec.dst.addr_bytes));
    //eth_spec.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    rte_flow_item_eth eth_mask = {0};
    //std::memset(eth_mask.src.addr_bytes, 0xFF, sizeof(eth_mask.src.addr_bytes));
    //std::memset(eth_mask.dst.addr_bytes, 0xFF, sizeof(eth_mask.dst.addr_bytes)); 
    //eth_mask.type = 0xFFFF;

    rte_flow_item_ipv4 ipv4_spec = {0};
    //std::memset(&ipv4_spec.hdr, 0x00, sizeof(ipv4_spec.hdr)); 
    rte_flow_item_ipv4 ipv4_mask = {0};
    //std::memset(&ipv4_mask.hdr, 0x00, sizeof(ipv4_mask.hdr));

    //ipv4_spec.hdr.dst_addr = htonl(((100<<24) + (10<<16) + (100<<8) + 241));    // The dest ip value to match the input packet.
    //ipv4_mask.hdr.dst_addr = 0xffffffff;            				  // The mask to apply to the dest ip. 
    ipv4_spec.hdr.src_addr = htonl(((10<<24) + (10<<16) + (8<<8) + 241));     	  // The src ip value to match the input packet. 
    ipv4_mask.hdr.src_addr = 0xffffffff;               				  // The mask to apply to the src ip. 

    rte_flow_action_queue flow_action_queue = {0};
    flow_action_queue.index = 1; 						  // The selected target queue.
    flow_actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    flow_actions[0].conf = &flow_action_queue;
    flow_actions[1].type = RTE_FLOW_ACTION_TYPE_END;
    flow_actions[1].conf = nullptr;

    flow_patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    flow_patterns[0].spec = nullptr; // &eth_spec;
    flow_patterns[0].last = nullptr;
    flow_patterns[0].mask = nullptr; // &eth_mask;

    flow_patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    flow_patterns[1].spec = &ipv4_spec;
    flow_patterns[1].last = nullptr;
    flow_patterns[1].mask = &ipv4_mask;

    flow_patterns[2].type = RTE_FLOW_ITEM_TYPE_END;
    flow_patterns[2].spec = nullptr;
    flow_patterns[2].last = nullptr;
    flow_patterns[2].mask = nullptr;

    return_val = rte_flow_validate(target_port_id, &flow_attr, flow_patterns, flow_actions, &flow_error);
    if (return_val != 0) {
	std::cerr << "rte_flow_validate failed. Return value: " << return_val << " RTE errno: " << rte_errno << std::endl;
	std::cerr << "RTE flow error type: " << flow_error.type << std::endl;
	std::cerr << "RTE flow error message: " << flow_error.message << std::endl;
	cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    flow = rte_flow_create(target_port_id, &flow_attr, flow_patterns, flow_actions, &flow_error);
    if (!flow) {
	std::cerr << "rte_flow_create failed. RTE errno: " << rte_errno << std::endl;
        std::cerr << "RTE flow error type: " << flow_error.type << std::endl;
        std::cerr << "RTE flow error message: " << flow_error.message << std::endl;
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }*/

    /*return_val = rte_eth_dev_info_get(target_port_id, &devInfo);
    if (return_val != 0) {
        printf("Error occurred while getting device info (port %u). Return code: %d", target_port_id, return_val);
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    std::cout << "RSS hash key size: " << devInfo.hash_key_size << std::endl;
    std::cout << "RSS RETA size: " << devInfo.reta_size << std::endl;
    std::cout << "RSS algorithm capabilities: " << devInfo.rss_algo_capa << std::endl;
    std::cout << "RSS flow type offloads: " << devInfo.flow_type_rss_offloads << std::endl;

    rte_eth_rss_conf rss_conf = {0};
    return_val = rte_eth_dev_rss_hash_conf_get(target_port_id, &rss_conf);
    if (return_val) {
        std::cout << "Unable to get RSS hash configuration. Target port id: " << target_port_id << " Return value: " << return_val << std::endl;
        cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
        exit(1);
    }

    std::cout << "Target port: " << target_port << " RSS hash configuration: " << std::endl;
    std::cout << "Algorithm: " << rss_conf.algorithm << std::endl;
    std::cout << "Supported hash functions: " << rss_conf.rss_hf << std::endl;
    std::cout << "Key length: " << std::to_string(rss_conf.rss_key_len) << std::endl;
    
    if (rss_conf.rss_key && rss_conf.rss_key_len) {
        uint8_t *key = new uint8_t[rss_conf.rss_key_len + 1];
        std::memcpy(key, rss_conf.rss_key, rss_conf.rss_key_len);
        key[rss_conf.rss_key_len] = 0x00;
        std::cout << "Key key: " << rss_conf.rss_key << std::endl;
    }*/

    // Checking the packet types parsing supported by the NIC.
    	check_supported_packet_types(target_port_id);
    //

    uint16_t lcoreIdx = 1;    
    // Initiating the packet reading and processing routines on the logical cores.
    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        auto packetReadingParams = new PacketReadingThreadParams;
        packetReadingParams->port_id = target_port_id;
        packetReadingParams->queue_id = i;
        packetReadingParams->num_packet_processing_workers = num_packet_processing_workers;
        packetReadingParams->timestamp_dynfield_offset = timestamp_dynfield_offset;

        if ((return_val = rte_eal_remote_launch(read_packets, reinterpret_cast<void *>(packetReadingParams), logicalCores[lcoreIdx])) != 0) {
            std::cerr << "Unable to launch packet reading routine on the logical core: %d. Return code: %d" << logicalCores[lcoreIdx] << return_val << std::endl;
            cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
            exit(1);
        }

        lcoreIdx++;

        // Initiating the packet processing threads.
        for (uint16_t j = 0; j < num_packet_processing_workers; ++j) {
            auto packetProcessingParams = new PacketProcessingThreadParams;
            packetProcessingParams->queue_id = i;
            packetProcessingParams->worker_id = j;
            packetProcessingParams->timestamp_dynfield_offset = timestamp_dynfield_offset;

            if ((return_val = rte_eal_remote_launch(process_packets, reinterpret_cast<void *>(packetProcessingParams), logicalCores[lcoreIdx])) != 0) {
                std::cerr << "Unable to launch packet processing routine on the logical core: %d. Return code: %d" << logicalCores[lcoreIdx] << return_val << std::endl;
                cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
                exit(1);
            }

            lcoreIdx++;
        }
    }

    if ((return_val = rte_eal_remote_launch(manage_acl_rules, nullptr, logicalCores[lcoreIdx])) != 0) {
                std::cerr << "Unable to launch rule manager routine on the logical core: %d. Return code: %d" << logicalCores[lcoreIdx] << return_val << std::endl;
                cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
                exit(1);
    }
    lcoreIdx++;

    auto statisticsThreadParams = new StatisticsThreadParams;
    statisticsThreadParams->port_id = target_port_id;
    statisticsThreadParams->num_rx_queues = num_rx_queues;
    statisticsThreadParams->num_packet_processing_workers = num_packet_processing_workers;

    // Logical core 0 will be displaying the statistics.
    get_and_print_nic_statistics(reinterpret_cast<void *>(statisticsThreadParams));  

    // Now we will wait for all the lcores (except main lcore = 0) to finish before we exit the application.
    for (uint16_t i = 1; i < logicalCores.size(); ++i) {
        std::cout << "Waiting for logical core " << logicalCores[i] << " to join. " << std::endl;
        rte_eal_wait_lcore(logicalCores[i]);
    }

    std::cout << "Exiting application ... " << std::endl;
    cleanup(target_port_id, num_rx_queues, num_packet_processing_workers);
    return 0;
}
