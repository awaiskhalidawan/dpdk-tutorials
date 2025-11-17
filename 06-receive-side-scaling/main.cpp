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

static volatile sig_atomic_t exit_indicator = 0;

void terminate(int signal) 
{
    exit_indicator = 1;
}

int read_packets_from_interface(void *param)
{
    const uint16_t port_id = (*(reinterpret_cast<uint32_t *>(param))) & 0xFFFF;
    const uint16_t queue_id = ((*(reinterpret_cast<uint32_t *>(param))) >> 16) & 0xFFFF;

    printf("Starting packet reading routine. Port Id: %u  Queue Id: %u  Logical core id (CPU Id): %d \n", port_id, queue_id, rte_lcore_id());
    rte_mbuf *rx_packets[32] = {nullptr};
    uint16_t rx_count = 0;

    // Now we go into a loop to continously check the port (ethernet interface) for any incoming packets. This process is called polling.
    while (!exit_indicator) {
        // Read the packets from interface. We read 32 packets at max at time.
        rx_count = rte_eth_rx_burst(port_id, queue_id, rx_packets, 32);

        if (rx_count == 0) {
            // No packets found. Check again.
            continue;
        }

        printf("Packet(s) received: %u          Port Id: %u   Queue Id: %u \n", rx_count, port_id, queue_id);

        // Free up the packets in bulk.
        rte_pktmbuf_free_bulk(rx_packets, rx_count);
    }
    
    std::cout << "Exiting packet reading routine. " << std::endl;
    return 0;
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

    // Detecting the logical cores (CPUs) ids passed to this DPDK application. 
    uint16_t i = 0;
    std::vector<uint16_t> logicalCores;
    std::cout << "Logical cores ids (CPU ids): ";
    RTE_LCORE_FOREACH(i) {
        logicalCores.push_back(i);
        std::cout << i << " ";
    }
    std::cout << std::endl;

    // We must have atleast two logical cores passed as an argument to this DPDK application. The first logical core will run the main function where 
    // we will run our packet reading loop. The second logical core will run our packet processing thread.
    if (logicalCores.size() < 2) 
    {
        std::cerr << "Atleast two logical cores are required to run this DPDK application. " << std::endl;
        exit(1);
    }

    uint16_t port_ids[RTE_MAX_ETHPORTS] = {0};
    int16_t id = 0;
    int16_t total_port_count = 0;
    
    // Detecting the available ports (ethernet interfaces) in the system.
    RTE_ETH_FOREACH_DEV(id) {
        port_ids[total_port_count] = id;
        total_port_count++;
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
        return 1;
    }

    std::cout << "Total ports detected: " << total_port_count << std::endl;

    // Creating memory pool which contains the memory buffers. A memory buffer is the buffer where DPDK driver will write an 
    // incoming packet. Below memory pool has name "mempool_1" and has 1023 available memory buffer. A single memory buffer 
    // has a size of RTE_MBUF_DEFAULT_BUF_SIZE (2048Bytes + 128Bytes).
    rte_mempool *memory_pool = rte_pktmbuf_pool_create("mempool_1", 1023, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    // Configuring the port (ethernet interface). An ethernet interface can have multiple receive queues and transmit queues. 
    // Currently we are setting up two receive queues and no transmit queue as we are not sending packets in this tutorial.
    const uint16_t rx_queues = 2;
    const uint16_t tx_queues = 0;

    rte_eth_conf portConf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = nullptr,                         // Using the default hash function by setting the rss_key to null.
                //.rss_key_len = 40,
                .rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_UDP      // RSS hash function is only applied to non-fragmented IPv4 packets. 
                                                            // The IPv4 non-fragmented packets will be distributed among the receive 
                                                            // queues according to the calculated RSS hash. All the packets other then
                                                            // IPv4 fragmented packets will be always be queued to queue 0. 
            }
        }
    };

    // We will fetch the device info to check how many receive queues are supported by our NIC. Atlease two queues are required
    // to test RSS (Receive Side Scaling).
    rte_eth_dev_info devInfo;
    return_val = rte_eth_dev_info_get(port_ids[0], &devInfo);
    if (return_val != 0) {
        printf("Error occurred while getting device info (port %u). Return code: %d", port_ids[0], return_val);
        rte_eal_cleanup();
        exit(1);
    }

    if (devInfo.max_rx_queues <= 1) {
        printf("Total Rx queues: %u found. Port Id: %u. Atleast two Rx queues are required to test RSS (Receive Side Scaling) in this tutorial. \n", devInfo.nb_rx_queues, port_ids[0]);
        rte_eal_cleanup();
        exit(1);
    }

    // Configure the port (ethernet interface).
    if ((return_val = rte_eth_dev_configure(port_ids[0], rx_queues, tx_queues, &portConf)) != 0) {
        std::cerr << "Unable to configure port. port Id: " << port_ids[0] << " Return code: "  << return_val << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    const int16_t portSocketId = rte_eth_dev_socket_id(port_ids[0]);
    const int16_t coreSocketId = rte_socket_id();

    // Configure the queue(s) of the port.
    for (uint16_t i = 0; i < rx_queues; i++) {
        return_val = rte_eth_rx_queue_setup(port_ids[0], i, 256, ((portSocketId >= 0) ? portSocketId : coreSocketId), nullptr, memory_pool);
        
        if (return_val < 0) {
            std::cerr << "Unable to setup Rx queue " << i << " Port Id: " << port_ids[0] << "Return code: " << return_val << std::endl;
            rte_eal_cleanup();
            exit(1);
        }

        std::cout << "Port Id: " << port_ids[0] << " Rx Queue: " << i << " setup successful. Socket id: "   
                  << ((portSocketId >= 0) ? portSocketId : coreSocketId) << std::endl;
    }

    // Enable promiscuous mode on the port. Not all the DPDK drivers provide the functionality to enable promiscuous mode. So we are going to 
    // ignore the result if the API fails.
    return_val = rte_eth_promiscuous_enable(port_ids[0]);
    if (return_val < 0) {
        std::cout << "Warning: Unable to set the promiscuous mode for port Id: " << port_ids[0] << " Return code: " << return_val << " Ignoring ... " << std::endl;
    }

    // All the configuration is done. Finally starting the port (ethernet interface) so that we can start receiving the packets.
    return_val = rte_eth_dev_start(port_ids[0]);
    if (return_val < 0) 
    {
        std::cout << "Unable to start port Id: " << port_ids[0] << " Return code: " << return_val << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    std::cout << "Port configuration successful. Port Id: " << port_ids[0] << std::endl;

    uint32_t port_and_queue_id = (1 << 16) | 0;   // Port Id: 0, Queue Id: 1 packed in uint32_t
    // Now initiating packet processing routine on the second logical core id.
    if ((return_val = rte_eal_remote_launch(read_packets_from_interface, reinterpret_cast<void *>(&port_and_queue_id), logicalCores[1])) != 0) 
    {
        std::cerr << "Unable to launch packet processing routine on the logical core: %d. Return code: %d" << logicalCores[1] << return_val << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    port_and_queue_id = (0 << 16) | 0;   // Port Id: 0, Queue Id: 0 packed in uint32_t.
    // Now initiating packet reading routine on the first logical core id. The first logical core id will always by used by main function of the DPDK application.
    read_packets_from_interface(reinterpret_cast<void *>(&port_and_queue_id));

    // Now we will wait for the packet processing routine to finish before we exit our DPDK application.
    rte_eal_wait_lcore(logicalCores[1]);

    std::cout << "Exiting DPDK program ... " << std::endl;
    rte_eal_cleanup();
    return 0;
}