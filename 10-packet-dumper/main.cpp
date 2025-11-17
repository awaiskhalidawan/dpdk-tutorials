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
#include <common.hpp>
#include <packet_dumper.hpp>

constexpr uint16_t NIC_STATISTICS_INTERVAL_MSEC       = 1000;        // 1 seconds.
constexpr uint32_t MEMORY_POOL_SIZE                   = 131071;      // Size of memory pool.
constexpr uint32_t RING_BUFFER_SIZE                   = 65536;       // Size of ring buffer.
constexpr uint32_t RX_BURST_SIZE                      = 32;          // Rx burst size.
constexpr uint32_t MAX_PACKET_PROCESSING_WORKER_COUNT = 4;           // Max packet processing worker count.
constexpr uint32_t NUM_QUEUE_RX_DESCRIPTORS           = 1024;        // Number of descriptors configured for Rx queue.
constexpr uint32_t MAX_ETH_RX_QUEUES                  = 4;           // Max number of Rx queues configured for ethernet port.
constexpr uint32_t MAX_PCAP_DUMP_FILE_SIZE_MB         = 200;         // Maximum size of pcap dump file in MB.
static const std::string MEMORY_POOL_NAME_PREFIX      = "mempool_";       // Prefix name of memory pool.
static const std::string RING_BUFFER_NAME_PREFIX      = "ring_buffer_";   // Ring buffer name prefix.

static std::atomic<bool> exit_indicator = false;

struct PacketReadingThreadParams 
{
    uint16_t port_id {std::numeric_limits<decltype(port_id)>::max()};
    uint16_t queue_id {std::numeric_limits<decltype(queue_id)>::max()};
    uint16_t num_packet_processing_workers_per_rx_queue {0};
    int32_t timestamp_dynfield_offset {-1};
};

struct StatisticsThreadParams
{
    std::string port;
    uint16_t port_id {std::numeric_limits<decltype(port_id)>::max()};
    uint16_t num_rx_queues {0};
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
};

static PacketReadingThreadStatistics packet_reading_thread_statistics[MAX_ETH_RX_QUEUES];

static rte_mempool **memory_pools {nullptr};

static rte_ring ***ring_buffers {nullptr}; 

static rte_flow *flow {nullptr};

void terminate(int signal) 
{
    exit_indicator.store(true, std::memory_order_relaxed);
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

int read_packets(void *param)
{
    if (!param) {
        return -1;
    }

    PacketReadingThreadParams *params = reinterpret_cast<PacketReadingThreadParams *>(param);
    const uint16_t port_id = params->port_id;
    const uint16_t queue_id = params->queue_id;
    const uint16_t num_packet_processing_workers_per_rx_queue = params->num_packet_processing_workers_per_rx_queue;
    const int32_t timestamp_dynfield_offset = params->timestamp_dynfield_offset;

    printf("Starting packet reading routine. Port Id: %u  Queue Id: %u  Logical core id (CPU Id): %d  Packet processing workers per rx queue count: %u \n", 
            port_id, queue_id, rte_lcore_id(), num_packet_processing_workers_per_rx_queue);

    rte_ring** ring_buffers = new rte_ring* [num_packet_processing_workers_per_rx_queue];
    if (!ring_buffers) {
        std::cerr << "Unable to allocate memory for ring buffers. " << std::endl;
        return -1;
    }

    for (uint16_t i = 0; i < num_packet_processing_workers_per_rx_queue; ++i) {
        const std::string ring_buffer_name = RING_BUFFER_NAME_PREFIX + std::to_string(queue_id) + "_" + std::to_string(i);
        ring_buffers[i] = rte_ring_lookup(ring_buffer_name.c_str());
        if (!ring_buffers[i]) {
            std::cerr << "Unable to lookup ring buffer: " << ring_buffer_name << std::endl;
            return -1;
        }
    }

    rte_mbuf *rx_packets[RX_BURST_SIZE] = {nullptr};
    uint64_t rx_count = 0;
    uint64_t ring_enqueue_count = 0;
    timespec ts {0};

    // Now we go into a loop to continously check the port (ethernet interface) for any incoming packets. This process is called polling.
    while (!exit_indicator.load(std::memory_order_relaxed)) {	    
	    // Read the packets from interface in bursts.
        rx_count = rte_eth_rx_burst(port_id, queue_id, rx_packets, RX_BURST_SIZE);

        if (rx_count == 0) {
            // No packets found. Check again.
            continue;
        }

        ATOMIC_INCREMENT_RELAXED(packet_reading_thread_statistics[queue_id].rx_packets, rx_count);
        
        // Timestamp the packets.
        clock_gettime(CLOCK_REALTIME, &ts);
        const uint64_t timestamp = (ts.tv_sec * 1000000000) + ts.tv_nsec;
        for (uint16_t i = 0; i < rx_count; ++i) {
            *(RTE_MBUF_DYNFIELD(rx_packets[i], timestamp_dynfield_offset, uint64_t *)) = timestamp;
        }

        for (uint16_t i = 0; i < num_packet_processing_workers_per_rx_queue; ++i) {
            ring_enqueue_count = rte_ring_enqueue_burst(ring_buffers[i], reinterpret_cast<void *const *>(rx_packets), rx_count, nullptr);
            
            // Free up the packets in bulk which are unable to enqueued on the ring buffer.
            if (ring_enqueue_count < rx_count) {
                rte_pktmbuf_free_bulk(&rx_packets[ring_enqueue_count], (rx_count - ring_enqueue_count));
            }
        }
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
    const auto statisticsThreadParams = reinterpret_cast<const StatisticsThreadParams *const>(param);
    const std::string port = statisticsThreadParams->port;
    const uint16_t port_id = statisticsThreadParams->port_id;
    const uint16_t num_rx_queues = statisticsThreadParams->num_rx_queues;

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
                std::cout << "Ethernet Port: " << port << " Statistics" << std::endl;
                std::cout << "----------------------------------------------" << std::endl;
                std::cout << "Statistics time: " << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X") << std::endl;
                std::cout << "Receive  packets: " << stats.ipackets << std::endl;
                std::cout << "Transmit packets: " << stats.opackets << std::endl;
                std::cout << "Receive  bytes: " << stats.ibytes << std::endl;
                std::cout << "Transmit bytes: " << stats.obytes << std::endl;
                std::cout << "Receive  errors: " << stats.ierrors << std::endl;
                std::cout << "Transmit errors: " << stats.oerrors << std::endl;
                std::cout << "Receive missed: " << stats.imissed << std::endl;
                std::cout << "Receive no memory buffers: " << stats.rx_nombuf << std::endl;
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

void cleanup(const uint16_t port_id, const uint16_t num_rx_queues, const uint16_t num_packet_processing_workers_per_rx_queue)
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
                for (uint16_t j = 0; j < num_packet_processing_workers_per_rx_queue; ++j) {
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
    if (return_val < 0) {
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

    std::string input_port;
    uint16_t num_rx_queues = 0;
    const uint16_t num_tx_queues = 0;
    const uint16_t num_packet_processing_workers_per_rx_queue = 1;

    for (uint16_t i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--input-port") == 0) {
            if ((i + 1) < argc) {
                input_port = argv[i + 1];
            } else {
                break;
            }
        }

        if (strcmp(argv[i], "--num-rx-queues") == 0) {
            if ((i + 1) < argc) {
                try {
                    num_rx_queues = std::stoi(argv[i + 1]);
                }
                catch(const std::exception& e) {
                    std::cerr << "Unable to get value of --num-rx-queues parameter. Error: " << e.what() << std::endl;
                    rte_eal_cleanup();
                    exit(1);
                }
            } else {
                break;
            }
        }
    }

    if (input_port.empty()) {
        std::cerr << "Input port not specified. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    if ((num_rx_queues == 0) || (num_rx_queues > MAX_ETH_RX_QUEUES)) {
        std::cerr << "Invalid number of Rx queues: " << num_rx_queues << ". Max Rx queues allowed: " << MAX_ETH_RX_QUEUES << std::endl;
        rte_eal_cleanup();
        exit(1);        
    }

    if ((num_packet_processing_workers_per_rx_queue == 0) || (num_packet_processing_workers_per_rx_queue > MAX_PACKET_PROCESSING_WORKER_COUNT)) {
        std::cerr << "Invalid number of packet processing workers per rx queue: " << num_packet_processing_workers_per_rx_queue << ". Max workers allowed per rx queue: " << MAX_PACKET_PROCESSING_WORKER_COUNT << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    // Check whether the target port is detected by the application.
    uint16_t input_port_id = std::numeric_limits<decltype(input_port_id)>::max();
    if (rte_eth_dev_get_port_by_name(input_port.c_str(), &input_port_id)) {
        std::cerr << "Unable to get port id against port: " << input_port << std::endl;
        rte_eal_cleanup();
        exit(1);
    }
    std::cout << "Input port: " << input_port << " detected by the application. Input port id: " << input_port_id << std::endl;

    // Detecting the logical cores (CPUs) ids passed to this DPDK application.
    uint16_t i = 0;
    std::vector<uint16_t> logicalCores;
    std::cout << "Logical cores ids (CPU ids): ";
    RTE_LCORE_FOREACH(i) {
        logicalCores.push_back(i);
        std::cout << i << " ";
    }
    std::cout << std::endl;

    // We need sufficient logical cores to run:
    // - main thread, rule manager thread, rule management server thread, packet receiving thread(s) and 
    //   packet processing thread(s).
    const uint16_t num_required_logical_cores = 1 + num_rx_queues + (num_rx_queues * num_packet_processing_workers_per_rx_queue);
    if (logicalCores.size() != num_required_logical_cores) {
        std::cerr << "Insufficient count of logical cores are provided. Required logical cores count: " << num_required_logical_cores << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

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
            cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
            exit(1);
        }
    }

    //Creating ring buffers for transfer of packets b/w packet reading and processing threads.
    ring_buffers = new rte_ring** [num_rx_queues];
    if (!ring_buffers) {
        std::cerr << "Unable to allocate memory for ring buffers ..." << std::endl;
        cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
        exit(1);
    }

    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        ring_buffers[i] = new rte_ring* [num_packet_processing_workers_per_rx_queue];
        if (!ring_buffers[i]) {
            std::cerr << "Unable to allocate memory for ring buffers ..." << std::endl;
            cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
            exit(1);
        }

        for (uint16_t j = 0; j < num_packet_processing_workers_per_rx_queue; ++j) {
            const std::string ring_buffer_name = RING_BUFFER_NAME_PREFIX + std::to_string(i) + "_" + std::to_string(j);
            ring_buffers[i][j] = rte_ring_create(ring_buffer_name.c_str(), RING_BUFFER_SIZE, rte_socket_id(), (RING_F_SP_ENQ | RING_F_SC_DEQ));
            if (!ring_buffers[i][j]) {
                std::cerr << "Unable to create ring buffer: " << ring_buffer_name << std::endl;
                cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
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
        }
    };

    if (num_rx_queues > 1) {
        portConf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;                          // Using the default hash function by setting the rss_key to null.
        portConf.rx_adv_conf.rss_conf.rss_key = nullptr;
        portConf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_UDP;  // RSS hash function is only applied to non-fragmented IPv4 packets. 
                                                                              // The IPv4 non-fragmented packets will be distributed among the receive 
                                                                              // queues according to the calculated RSS hash. All the packets other then
                                                                              // UDP IPv4 fragmented packets will be always be queued to queue 0. 
    }

    // We will fetch the device info to check how many receive queues are supported by our ethernet device.
    rte_eth_dev_info devInfo;
    return_val = rte_eth_dev_info_get(input_port_id, &devInfo);
    if (return_val != 0) {
        printf("Error occurred while getting device info (port %u). Return code: %d", input_port_id, return_val);
        cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
        exit(1);
    }

    if (num_rx_queues > devInfo.max_rx_queues) {
        std::cerr << "Configured Rx queues: " << num_rx_queues << " exceeds the available device Rx queues: " 
                  << devInfo.max_rx_queues << std::endl;
        cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
        exit(1);
    }

    // Configure the port (ethernet interface).
    if ((return_val = rte_eth_dev_configure(input_port_id, num_rx_queues, num_tx_queues, &portConf)) != 0) {
        std::cerr << "Unable to configure port. port Id: " << input_port_id << " Return code: "  << return_val << std::endl;
        cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
        exit(1);
    }

    const int16_t portSocketId = rte_eth_dev_socket_id(input_port_id);
    const int16_t coreSocketId = rte_socket_id();

    // Configure the queue(s) of the port.
    for (uint16_t i = 0; i < num_rx_queues; i++) {
        return_val = rte_eth_rx_queue_setup(input_port_id, i, NUM_QUEUE_RX_DESCRIPTORS, ((portSocketId >= 0) ? portSocketId : coreSocketId), nullptr, 
                                            memory_pools[i]);
        
        if (return_val < 0) {
            std::cerr << "Unable to setup Rx queue: " << i << " Port Id: " << input_port_id << " Return code: " << return_val << std::endl;
            cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
            exit(1);
        }

        std::cout << "Port Id: " << input_port_id << " Rx Queue: " << i << " setup successful. Port Socket Id: "   
                  << portSocketId << " Core Socket Id: " << coreSocketId << std::endl;
    }

    // Enable promiscuous mode on the port. Not all the DPDK drivers provide the functionality to enable promiscuous mode. So we are going to 
    // ignore the result if the API fails.
    return_val = rte_eth_promiscuous_enable(input_port_id);
    if (return_val < 0) {
        std::cout << "Warning: Unable to set the promiscuous mode for port Id: " << input_port_id << " Return code: " << return_val << " Ignoring ... " << std::endl;
    }

    // All the configuration is done. Finally starting the port (ethernet interface) so that we can start receiving the packets.
    return_val = rte_eth_dev_start(input_port_id);
    if (return_val < 0) {
        std::cout << "Unable to start port. Port Id: " << input_port_id << " Return code: " << return_val << std::endl;
        cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
        exit(1);
    }

    std::cout << "Port configuration successful. Port Id: " << input_port_id << std::endl;

    uint16_t lcoreIdx = 1;    
    // Initiating the packet reading and processing routines on the logical cores.
    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        auto packetReadingParams = new PacketReadingThreadParams;
        packetReadingParams->port_id = input_port_id;
        packetReadingParams->queue_id = i;
        packetReadingParams->num_packet_processing_workers_per_rx_queue = num_packet_processing_workers_per_rx_queue;
        packetReadingParams->timestamp_dynfield_offset = timestamp_dynfield_offset;

        if ((return_val = rte_eal_remote_launch(read_packets, reinterpret_cast<void *>(packetReadingParams), logicalCores[lcoreIdx])) != 0) {
            std::cerr << "Unable to launch packet reading routine on the logical core: %d. Return code: %d" << logicalCores[lcoreIdx] << return_val << std::endl;
            cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
            exit(1);
        }

        lcoreIdx++;

        // Initiating the packet processing threads.
        for (uint16_t j = 0; j < num_packet_processing_workers_per_rx_queue; ++j) {
            auto packetProcessingParams = new PacketProcessingThreadParams;
            packetProcessingParams->queue_id = i;
            packetProcessingParams->worker_id = j;
            packetProcessingParams->timestamp_dynfield_offset = timestamp_dynfield_offset;

            if ((return_val = rte_eal_remote_launch(process_packets, reinterpret_cast<void *>(packetProcessingParams), logicalCores[lcoreIdx])) != 0) {
                std::cerr << "Unable to launch packet processing routine on the logical core: %d. Return code: %d" << logicalCores[lcoreIdx] << return_val << std::endl;
                cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
                exit(1);
            }

            lcoreIdx++;
        }
    }

    auto statisticsThreadParams = new StatisticsThreadParams;
    statisticsThreadParams->port = input_port;
    statisticsThreadParams->port_id = input_port_id;
    statisticsThreadParams->num_rx_queues = num_rx_queues;

    // Logical core 0 will be displaying the statistics.
    get_and_print_nic_statistics(reinterpret_cast<void *>(statisticsThreadParams));

    // Now we will wait for all the lcores (except main lcore = 0) to finish before we exit the application.
    for (uint16_t i = 1; i < logicalCores.size(); ++i) {
        std::cout << "Waiting for logical core " << logicalCores[i] << " to join. " << std::endl;
        rte_eal_wait_lcore(logicalCores[i]);
    }

    std::cout << "Exiting application ... " << std::endl;
    cleanup(input_port_id, num_rx_queues, num_packet_processing_workers_per_rx_queue);
    return 0;
}
