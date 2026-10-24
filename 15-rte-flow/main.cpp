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
#include <thread>
#include <csignal>
#include <vector>
#include <atomic>
#include <cstring>
#include <limits>
#include <chrono>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <flow_util.hpp>

constexpr uint16_t MAX_ETH_RX_QUEUES = 4;
constexpr uint16_t DEFAULT_NUM_RX_QUEUES = 2;
constexpr uint16_t DEFAULT_REDIRECT_PORT = 5000;
constexpr uint16_t DEFAULT_DROP_PORT = 5001;
constexpr uint16_t DEFAULT_TARGET_QUEUE = 1;
constexpr uint32_t MEMORY_POOL_SIZE = 8191;
constexpr uint16_t NUM_QUEUE_RX_DESCRIPTORS = 256;
constexpr uint16_t RX_BURST_SIZE = 32;
constexpr uint16_t STATISTICS_INTERVAL_SEC = 1;

static std::atomic<bool> exit_indicator {false};
static std::atomic<uint64_t> queue_rx_packets[MAX_ETH_RX_QUEUES];

static struct rte_flow *queue_redirect_flow {nullptr};
static struct rte_flow *drop_flow {nullptr};
static rte_mempool *memory_pool {nullptr};

void terminate(int /*signal*/)
{
    exit_indicator.store(true, std::memory_order_relaxed);
}

struct PacketReadingThreadParams
{
    uint16_t port_id {std::numeric_limits<uint16_t>::max()};
    uint16_t queue_id {std::numeric_limits<uint16_t>::max()};
};

// Poll one RX queue. Matched redirect traffic should land on --target-queue.
// Dropped traffic should never appear on any queue.
int read_packets_from_interface(void *param)
{
    auto *params = reinterpret_cast<PacketReadingThreadParams *>(param);
    const uint16_t port_id = params->port_id;
    const uint16_t queue_id = params->queue_id;

    std::cout << "Starting packet reading routine. Port Id: " << port_id
              << " Queue Id: " << queue_id
              << " Logical core id (CPU Id): " << rte_lcore_id() << std::endl;

    rte_mbuf *rx_packets[RX_BURST_SIZE] = {nullptr};

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        const uint16_t rx_count = rte_eth_rx_burst(port_id, queue_id, rx_packets, RX_BURST_SIZE);
        if (rx_count == 0) {
            continue;
        }

        queue_rx_packets[queue_id].fetch_add(rx_count, std::memory_order_relaxed);
        rte_pktmbuf_free_bulk(rx_packets, rx_count);
    }

    delete params;
    std::cout << "Exiting packet reading routine. Queue Id: " << queue_id << std::endl;
    return 0;
}

void print_statistics(const uint16_t port_id, const uint16_t num_rx_queues,
                      const uint16_t redirect_port, const uint16_t drop_port,
                      const uint16_t target_queue)
{
    std::cout << "Starting statistics routine on logical core: " << rte_lcore_id() << std::endl;

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        std::cout << std::endl;
        std::cout << "RTE Flow RX Statistics (port Id: " << port_id << ")" << std::endl;
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << " Redirect UDP dport " << redirect_port
                  << " -> queue " << target_queue << std::endl;
        std::cout << " Drop UDP dport " << drop_port
                  << " (should not appear on any queue)" << std::endl;
        std::cout << "----------------------------------------------" << std::endl;

        uint64_t app_rx_total = 0;
        for (uint16_t i = 0; i < num_rx_queues; ++i) {
            const uint64_t queue_packets = queue_rx_packets[i].load(std::memory_order_relaxed);
            app_rx_total += queue_packets;
            std::cout << " Queue " << i << " packets (app): "
                      << queue_packets << std::endl;
        }

        rte_eth_stats nic_stats {};
        if (rte_eth_stats_get(port_id, &nic_stats) == 0) {
            std::cout << "----------------------------------------------" << std::endl;
            std::cout << " NIC statistics (hardware)" << std::endl;
            std::cout << "  ipackets (delivered to host): " << nic_stats.ipackets << std::endl;
            std::cout << "  ibytes:  " << nic_stats.ibytes << std::endl;
            std::cout << "  imissed (Rx queue full):     " << nic_stats.imissed << std::endl;
            std::cout << "  ierrors:                     " << nic_stats.ierrors << std::endl;
            std::cout << "  rx_nombuf:                   " << nic_stats.rx_nombuf << std::endl;
            std::cout << "  app_rx_total (q0+q1):        " << app_rx_total << std::endl;
            if (nic_stats.ipackets >= app_rx_total) {
                std::cout << "  nic_ipackets - app_rx_total: "
                          << (nic_stats.ipackets - app_rx_total)
                          << " (should be ~0 if app drains all queues)" << std::endl;
            }
        } else {
            std::cerr << " Unable to read NIC statistics for port Id: " << port_id << std::endl;
        }
        std::cout << "----------------------------------------------" << std::endl;

        std::this_thread::sleep_for(std::chrono::seconds(STATISTICS_INTERVAL_SEC));
    }
}

void cleanup(const uint16_t port_id)
{
    destroy_flow_rule(port_id, queue_redirect_flow, "queue-redirect");
    queue_redirect_flow = nullptr;

    destroy_flow_rule(port_id, drop_flow, "drop");
    drop_flow = nullptr;

    if (rte_eth_dev_is_valid_port(port_id)) {
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }

    if (memory_pool != nullptr) {
        rte_mempool_free(memory_pool);
        memory_pool = nullptr;
    }

    rte_eal_cleanup();
}

void print_usage(const char *prog_name)
{
    std::cerr << "Usage: " << prog_name
              << " <eal-args> -- --port <pci_address>"
              << " [--num-rx-queues <N>]"
              << " [--redirect-port <udp_dport>]"
              << " [--drop-port <udp_dport>]"
              << " [--target-queue <queue_id>]" << std::endl;
}

int main(int argc, char **argv)
{
    struct sigaction action;
    std::memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = terminate;
    sigaction(SIGTERM, &action, nullptr);
    sigaction(SIGINT, &action, nullptr);

    std::cout << "Starting DPDK RTE Flow tutorial ... " << std::endl;

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
    argc -= return_val;
    argv += return_val;

    std::string port;
    uint16_t num_rx_queues = DEFAULT_NUM_RX_QUEUES;
    uint16_t redirect_port = DEFAULT_REDIRECT_PORT;
    uint16_t drop_port = DEFAULT_DROP_PORT;
    uint16_t target_queue = DEFAULT_TARGET_QUEUE;
    const uint16_t num_tx_queues = 0;

    for (uint16_t i = 0; i < static_cast<uint16_t>(argc); ++i) {
        if (strcmp(argv[i], "--port") == 0) {
            if ((i + 1) < argc) {
                port = argv[i + 1];
            }
        } else if (strcmp(argv[i], "--num-rx-queues") == 0) {
            if ((i + 1) < argc) {
                try {
                    num_rx_queues = static_cast<uint16_t>(std::stoi(argv[i + 1]));
                } catch (const std::exception &e) {
                    std::cerr << "Unable to parse --num-rx-queues. Error: " << e.what() << std::endl;
                    rte_eal_cleanup();
                    exit(1);
                }
            }
        } else if (strcmp(argv[i], "--redirect-port") == 0) {
            if ((i + 1) < argc) {
                try {
                    redirect_port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
                } catch (const std::exception &e) {
                    std::cerr << "Unable to parse --redirect-port. Error: " << e.what() << std::endl;
                    rte_eal_cleanup();
                    exit(1);
                }
            }
        } else if (strcmp(argv[i], "--drop-port") == 0) {
            if ((i + 1) < argc) {
                try {
                    drop_port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
                } catch (const std::exception &e) {
                    std::cerr << "Unable to parse --drop-port. Error: " << e.what() << std::endl;
                    rte_eal_cleanup();
                    exit(1);
                }
            }
        } else if (strcmp(argv[i], "--target-queue") == 0) {
            if ((i + 1) < argc) {
                try {
                    target_queue = static_cast<uint16_t>(std::stoi(argv[i + 1]));
                } catch (const std::exception &e) {
                    std::cerr << "Unable to parse --target-queue. Error: " << e.what() << std::endl;
                    rte_eal_cleanup();
                    exit(1);
                }
            }
        }
    }

    if (port.empty()) {
        std::cerr << "Port not specified. " << std::endl;
        print_usage("rte-flow");
        rte_eal_cleanup();
        exit(1);
    }

    if ((num_rx_queues < 2) || (num_rx_queues > MAX_ETH_RX_QUEUES)) {
        std::cerr << "Invalid --num-rx-queues: " << num_rx_queues
                  << ". Allowed range: 2 .. " << MAX_ETH_RX_QUEUES << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    if (target_queue == 0 || target_queue >= num_rx_queues) {
        std::cerr << "Invalid --target-queue: " << target_queue
                  << ". Must be in range 1 .. " << (num_rx_queues - 1)
                  << " so queue 0 remains the default/unmatched queue." << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    if (redirect_port == drop_port) {
        std::cerr << "--redirect-port and --drop-port must be different." << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    for (uint16_t i = 0; i < MAX_ETH_RX_QUEUES; ++i) {
        queue_rx_packets[i].store(0, std::memory_order_relaxed);
    }

    // Resolve PCI address to DPDK port id.
    uint16_t port_id = std::numeric_limits<uint16_t>::max();
    if (rte_eth_dev_get_port_by_name(port.c_str(), &port_id) != 0) {
        std::cerr << "Unable to get port id against port: " << port << std::endl;
        rte_eal_cleanup();
        exit(1);
    }
    std::cout << "Port: " << port << " detected. Port Id: " << port_id << std::endl;

    // Detect logical cores passed to this DPDK application.
    // We need: 1 main/stats core + 1 core per RX queue.
    uint16_t lcore_id = 0;
    std::vector<uint16_t> logical_cores;
    std::cout << "Logical cores ids (CPU ids): ";
    RTE_LCORE_FOREACH(lcore_id) {
        logical_cores.push_back(lcore_id);
        std::cout << lcore_id << " ";
    }
    std::cout << std::endl;

    const uint16_t num_required_logical_cores = 1 + num_rx_queues;
    if (logical_cores.size() < num_required_logical_cores) {
        std::cerr << "Insufficient logical cores. Required: " << num_required_logical_cores
                  << " (1 stats/main + " << num_rx_queues << " RX workers). Provided: "
                  << logical_cores.size() << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    // Creating memory pool which contains the memory buffers. A memory buffer is the buffer where DPDK driver will write an
    // incoming packet.
    memory_pool = rte_pktmbuf_pool_create("mempool_rte_flow", MEMORY_POOL_SIZE, 512, 0,
                                          RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (memory_pool == nullptr) {
        std::cerr << "Unable to create memory pool. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    // Use MQ_RX_NONE so unmatched traffic stays on queue 0. Explicit rte_flow
    // QUEUE actions then steer selected packets to --target-queue. This makes
    // the hardware steering effect easy to observe in the per-queue counters.
    rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_NONE,
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };

    rte_eth_dev_info dev_info;
    return_val = rte_eth_dev_info_get(port_id, &dev_info);
    if (return_val != 0) {
        std::cerr << "Unable to get device info. Port Id: " << port_id
                  << " Return code: " << return_val << std::endl;
        cleanup(port_id);
        exit(1);
    }

    if (num_rx_queues > dev_info.max_rx_queues) {
        std::cerr << "Configured Rx queues: " << num_rx_queues
                  << " exceeds device max Rx queues: " << dev_info.max_rx_queues << std::endl;
        cleanup(port_id);
        exit(1);
    }

    if ((return_val = rte_eth_dev_configure(port_id, num_rx_queues, num_tx_queues, &port_conf)) != 0) {
        std::cerr << "Unable to configure port. Port Id: " << port_id
                  << " Return code: " << return_val << std::endl;
        cleanup(port_id);
        exit(1);
    }

    const int16_t port_socket_id = rte_eth_dev_socket_id(port_id);
    const int16_t core_socket_id = static_cast<int16_t>(rte_socket_id());

    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        return_val = rte_eth_rx_queue_setup(port_id, i, NUM_QUEUE_RX_DESCRIPTORS,
                                            (port_socket_id >= 0) ? port_socket_id : core_socket_id,
                                            nullptr, memory_pool);
        if (return_val < 0) {
            std::cerr << "Unable to setup Rx queue: " << i << " Port Id: " << port_id
                      << " Return code: " << return_val << std::endl;
            cleanup(port_id);
            exit(1);
        }
        std::cout << "Port Id: " << port_id << " Rx Queue: " << i << " setup successful." << std::endl;
    }

    // Enable promiscuous mode on the port. Not all the DPDK drivers provide the functionality to enable promiscuous mode. So we are going to
    // ignore the result if the API fails.
    return_val = rte_eth_promiscuous_enable(port_id);
    if (return_val < 0) {
        std::cout << "Warning: Unable to set promiscuous mode for port Id: " << port_id
                  << " Return code: " << return_val << " Ignoring ... " << std::endl;
    }

    return_val = rte_eth_dev_start(port_id);
    if (return_val < 0) {
        std::cerr << "Unable to start port. Port Id: " << port_id
                  << " Return code: " << return_val << std::endl;
        cleanup(port_id);
        exit(1);
    }

    std::cout << "Port configuration successful. Port Id: " << port_id << std::endl;

    if (rte_eth_stats_reset(port_id) != 0) {
        std::cout << "Warning: Unable to reset NIC statistics for port Id: " << port_id << std::endl;
    }

    // Print flow engine capabilities. Support varies by NIC/PMD (ixgbe, i40e, mlx5, ...).
    print_flow_info(port_id);

    // Install hardware flow rules.
    // Rule 1: IPv4/UDP dport == redirect_port  -> QUEUE(target_queue)
    // Rule 2: IPv4/UDP dport == drop_port      -> DROP
    // Unmatched packets continue to arrive on queue 0.
    queue_redirect_flow = create_queue_redirect_rule(port_id, redirect_port, target_queue);
    if (queue_redirect_flow == nullptr) {
        std::cerr << "Failed to install queue redirect rule. Exiting." << std::endl;
        cleanup(port_id);
        exit(1);
    }

    drop_flow = create_drop_rule(port_id, drop_port);
    if (drop_flow == nullptr) {
        std::cerr << "Failed to install drop rule. Exiting." << std::endl;
        cleanup(port_id);
        exit(1);
    }

    // Launch one RX worker per queue on dedicated lcores.
    uint16_t lcore_idx = 1;
    for (uint16_t i = 0; i < num_rx_queues; ++i) {
        auto *params = new PacketReadingThreadParams;
        params->port_id = port_id;
        params->queue_id = i;

        if ((return_val = rte_eal_remote_launch(read_packets_from_interface,
                                                reinterpret_cast<void *>(params),
                                                logical_cores[lcore_idx])) != 0) {
            std::cerr << "Unable to launch packet reading routine on logical core: "
                      << logical_cores[lcore_idx] << " Return code: " << return_val << std::endl;
            exit_indicator.store(true, std::memory_order_relaxed);
            cleanup(port_id);
            exit(1);
        }
        ++lcore_idx;
    }

    // Main lcore prints per-queue counters so readers can verify hardware steering.
    print_statistics(port_id, num_rx_queues, redirect_port, drop_port, target_queue);

    for (uint16_t i = 1; i < num_required_logical_cores; ++i) {
        std::cout << "Waiting for logical core " << logical_cores[i] << " to join." << std::endl;
        rte_eal_wait_lcore(logical_cores[i]);
    }

    std::cout << "Exiting DPDK RTE Flow tutorial ... " << std::endl;
    cleanup(port_id);
    return 0;
}
