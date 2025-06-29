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
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <atomic>
#include <iomanip>
#include <vector>

constexpr uint16_t NIC_STATISTICS_INTERVAL_MSEC = 1000;         // 1 seconds.
static const std::string MEMORY_POOL_NAME = "mempool_1";        // Name of the memory pool.
constexpr uint32_t MEMORY_POOL_SIZE = 65535;                    // Size of the memory pool.

static std::atomic<bool> exit_indicator = false;

void terminate(int signal) 
{
    exit_indicator.store(true, std::memory_order_relaxed);
}

bool check_device_offloading_support(const uint16_t portId, rte_eth_dev_info &devInfo)
{
    int32_t ret = rte_eth_dev_info_get(portId, &devInfo);
    if (ret != 0) {
      printf("Error occurred while getting device info (port %u). Return code: %d", portId, ret);
      return false;
    }

    printf("-----------------------------------------------------------------------------\n");
    // Tx Capabilities
    printf("Tx Offloading Capabilities for ethernet device (port): %d\n", portId);
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VLAN_INSERT      ) {
        printf("  RTE_ETH_TX_OFFLOAD_VLAN_INSERT");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM       ) {
        printf("  RTE_ETH_TX_OFFLOAD_IPV4_CKSUM");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM        ) {
        printf("  RTE_ETH_TX_OFFLOAD_UDP_CKSUM");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM        ) {
        printf("  RTE_ETH_TX_OFFLOAD_TCP_CKSUM");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SCTP_CKSUM       ) {
        printf("  RTE_ETH_TX_OFFLOAD_SCTP_CKSUM");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO          ) {
        printf("  RTE_ETH_TX_OFFLOAD_TCP_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_TSO          ) {
        printf("  RTE_ETH_TX_OFFLOAD_UDP_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM ) {
        printf("  RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_QINQ_INSERT      ) {
        printf("  RTE_ETH_TX_OFFLOAD_QINQ_INSERT");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO    ) {
        printf("  RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO      ) {
        printf("  RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO     ) {
        printf("  RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO   ) {
        printf("  RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MACSEC_INSERT    ) {
        printf("  RTE_ETH_TX_OFFLOAD_MACSEC_INSERT");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MT_LOCKFREE      ) {
        printf("  RTE_ETH_TX_OFFLOAD_MT_LOCKFREE");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS       ) {
        printf("  RTE_ETH_TX_OFFLOAD_MULTI_SEGS");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE   ) {
        printf("  RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SECURITY         ) {
        printf("  RTE_ETH_TX_OFFLOAD_SECURITY");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_TNL_TSO      ) {
        printf("  RTE_ETH_TX_OFFLOAD_UDP_TNL_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IP_TNL_TSO       ) {
        printf("  RTE_ETH_TX_OFFLOAD_IP_TNL_TSO");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM  ) {
        printf("  RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM");
    }
    if (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP) {
        printf("  RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP");
    }

    printf("\n");

    // Rx Capabilities
    printf("Rx Offloading Capabilities for Port: %d\n", portId);
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP       ) {
        printf("  RTE_ETH_RX_OFFLOAD_VLAN_STRIP");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM       ) {
        printf("  RTE_ETH_RX_OFFLOAD_IPV4_CKSUM");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM        ) {
        printf("  RTE_ETH_RX_OFFLOAD_UDP_CKSUM");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM        ) {
        printf("  RTE_ETH_RX_OFFLOAD_TCP_CKSUM");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO          ) {
        printf("  RTE_ETH_RX_OFFLOAD_TCP_LRO");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_QINQ_STRIP       ) {
        printf("  RTE_ETH_RX_OFFLOAD_QINQ_STRIP");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM ) {
        printf("  RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_MACSEC_STRIP     ) {
        printf("  RTE_ETH_RX_OFFLOAD_MACSEC_STRIP");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_FILTER      ) {
        printf("  RTE_ETH_RX_OFFLOAD_VLAN_FILTER");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_EXTEND      ) {
        printf("  RTE_ETH_RX_OFFLOAD_VLAN_EXTEND");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER          ) {
        printf("  RTE_ETH_RX_OFFLOAD_SCATTER");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP        ) {
        printf("  RTE_ETH_RX_OFFLOAD_TIMESTAMP");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SECURITY         ) {
        printf("  RTE_ETH_RX_OFFLOAD_SECURITY");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_KEEP_CRC         ) {
        printf("  RTE_ETH_RX_OFFLOAD_KEEP_CRC");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCTP_CKSUM       ) {
        printf("  RTE_ETH_RX_OFFLOAD_SCTP_CKSUM");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM  ) {
        printf("  RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_RSS_HASH         ) {
        printf("  RTE_ETH_RX_OFFLOAD_RSS_HASH");
    }
    if (devInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT     ) {
        printf("  RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT");
    }

    printf("\n");
    printf("Max Rx Queues: %u\n", devInfo.max_rx_queues);
    printf("Max Tx Queues: %u\n", devInfo.max_tx_queues);
    printf("-----------------------------------------------------------------------------\n");

    return true;
}

bool prepare_memory_pool()
{
    rte_mempool* mempool = rte_mempool_lookup(MEMORY_POOL_NAME.c_str());
    if (!mempool) {
        std::cerr << "Unable to lookup mempool: " << MEMORY_POOL_NAME << std::endl;
        return false;
    }

    std::vector<rte_mbuf *> memory_buffers;
    memory_buffers.resize(MEMORY_POOL_SIZE);

    uint32_t i = 0;
    for (; i < MEMORY_POOL_SIZE; ++i) {
        rte_mbuf* buffer = rte_pktmbuf_alloc(mempool);

        memory_buffers[i] = buffer;
    }

    if (i != MEMORY_POOL_SIZE) {
        std::cerr << "Not all the memory buffers are available in mempool: " << MEMORY_POOL_NAME << std::endl;
        return false;
    }

    uint8_t temp = 0;

    for (uint32_t j = 0; j < memory_buffers.size(); ++j) {
        // Prepare the memory buffer.
        rte_mbuf* buf = memory_buffers[j];

        // We will get a pointer to the main memory area of our memory buffer and write packet info.
        uint8_t *data = rte_pktmbuf_mtod(buf, uint8_t *);

        // Setting Ethernet header information (Source MAC, Destination MAC, Ethernet type).
        rte_ether_hdr *const eth_hdr = reinterpret_cast<rte_ether_hdr *>(data);
        eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        const uint8_t src_mac_addr[6] = {0x08, 0x00, 0x27, 0x95, 0xBD, temp};
        memcpy(eth_hdr->src_addr.addr_bytes, src_mac_addr, sizeof(src_mac_addr));

        const uint8_t dst_mac_addr[6] = {0x08, 0x00, 0x27, 0x35, 0x14, temp};
        memcpy(eth_hdr->dst_addr.addr_bytes, dst_mac_addr, sizeof(dst_mac_addr));

        // Setting IPv4 header information.
        rte_ipv4_hdr *const ipv4_hdr = reinterpret_cast<rte_ipv4_hdr *>(data + sizeof(rte_ether_hdr));
        ipv4_hdr->version = 4;              // Setting IP version as IPv4
        ipv4_hdr->ihl = 5;                  // Setting IP header length = 20 bytes = (5 * 4 Bytes)
        ipv4_hdr->type_of_service = 0;      // Setting DSCP = 0; ECN = 0;
        ipv4_hdr->total_length = rte_cpu_to_be_16(200);       // Setting total IPv4 packet length to 200 bytes. This includes the IPv4 header (20 bytes) as well.
        ipv4_hdr->packet_id = 0;            // Setting identification = 0 as the packet is non-fragmented.
        ipv4_hdr->fragment_offset = 0x0040; // Setting packet as non-fragmented and fragment offset = 0.
        ipv4_hdr->time_to_live = 64;        // Setting Time to live = 64;
        ipv4_hdr->next_proto_id = 17;       // Setting the next protocol as UDP (17).

        const uint8_t src_ip_addr[4] = {10, 10, 8, temp};
        memcpy(&ipv4_hdr->src_addr, src_ip_addr, sizeof(src_ip_addr));      // Setting source ip address = 1.2.3.4

        const uint8_t dest_ip_addr[4] = {100, 10, 100, temp};
        memcpy(&ipv4_hdr->dst_addr, dest_ip_addr, sizeof(dest_ip_addr));    // Setting destination ip address = 4.3.2.1

        ++temp;

        ipv4_hdr->hdr_checksum = 0;
        //ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);      // Calculating and setting IPv4 checksum in IPv4 header.

        // Setting UDP header information.
        rte_udp_hdr *const udp_hdr = reinterpret_cast<rte_udp_hdr *>(data + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr));
        udp_hdr->dst_port = rte_cpu_to_be_16(5566 + temp);     // Setting destination port.
        udp_hdr->src_port = rte_cpu_to_be_16(9988 + temp);     // Setting source port.
        udp_hdr->dgram_len = rte_cpu_to_be_16(180);     // Setting datagram length.
        udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr, 0); // Setting checksum of ip psuedo header.

        // Setting data in the UDP payload
        uint8_t *payload = data + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr);
        memset(payload, 0, 172);
        const char sample_data[] = {"This is a sample data generated by a DPDK application ..."};
        memcpy(payload, sample_data, sizeof(sample_data));

        // Return the memory buffer to memory pool.
        rte_pktmbuf_free(buf);
        buf = memory_buffers[j] = nullptr;
    }

    memory_buffers.clear();
    return true;
}

int get_and_print_nic_statistics(const uint16_t port_id)
{
    int return_val = -1;
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
            //std::cout << "\033[2J\033[1;1H";
            if ((return_val = rte_eth_stats_get(port_id, &stats) == 0)) {
                auto now = std::chrono::system_clock::now();
                auto in_time_t = std::chrono::system_clock::to_time_t(now);

                const double rx_packet_rate = (static_cast<double>(stats.ipackets - last_rx_packets) / (static_cast<double>(diff.count()) / 1000.0)) / (1024.0 * 1024.0);
                last_rx_packets = stats.ipackets;
                const double tx_packet_rate = (static_cast<double>(stats.opackets - last_tx_packets) / (static_cast<double>(diff.count()) / 1000.0)) / (1024.0 * 1024.0);
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
                std::cout << "Receive  packet rate (mpps): " << rx_packet_rate << std::endl;
                std::cout << "Transmit packet rate (mpps): " << tx_packet_rate << std::endl;
                std::cout << "----------------------------------------------" << std::endl;
                std::cout << std::endl;
            } else {
                std::cerr << "Unable to get ethernet device statistics. Port id: " << port_id << " Return value: " << return_val << std::endl;
            }
        }

        using namespace std::literals;
        std::this_thread::sleep_for(50ms);
    }

    return 0;
}

int transmit_packets_from_interface(void* param)
{
    if (!param) {
        std::cerr << "Unable to start packet transmission routine. Parameters are null. " << std::endl;
        return -1;
    }

    rte_mempool* mempool = rte_mempool_lookup(MEMORY_POOL_NAME.c_str());
    if (!mempool) {
        std::cerr << "Unable to lookup mempool: " << MEMORY_POOL_NAME << std::endl;
        return -1;
    }


    const uint16_t port_id = (*static_cast<uint32_t *>(param)) >> 16;
    const uint16_t queue_id = (*static_cast<uint32_t *>(param)) & 0xFFFF;
    std::cout << "Starting packet transmission routine on logical core: " << rte_lcore_id() << " Port id: " << port_id << " Queue id: " << queue_id << std::endl;


    const uint64_t packet_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + 172;
    const uint64_t packets_per_second = 7000000;
    const uint64_t packet_tx_burst_size = 16;
    const uint64_t interburst_time_ns = (1 * 1000000000) / (packets_per_second / packet_tx_burst_size);

    
    //rte_mbuf *packet = nullptr;
    rte_mbuf *packets[packet_tx_burst_size];

    timespec ts {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t t0 = ts.tv_sec * 1000000000 + ts.tv_nsec;
    uint64_t t1 = t0 + interburst_time_ns;
    uint64_t tx_count = 0;

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        while (t0 < t1) {
            clock_gettime(CLOCK_MONOTONIC, &ts);
            t0 = ts.tv_sec * 1000000000 + ts.tv_nsec;            
        }
        t1 += interburst_time_ns;

        /*packet = rte_pktmbuf_alloc(mempool);
        if (!packet) {
            std::cerr << "Unable to get memory buffer from mempool. " << std::endl;
            using namespace std::literals;
            std::this_thread::sleep_for(50ms);            
            continue;
        }*/

        if (rte_pktmbuf_alloc_bulk(mempool, packets, packet_tx_burst_size)) {
            std::cerr << "Unable to allocate the memory buffer in bulk from mempool. " << std::endl;
            using namespace std::literals;
            std::this_thread::sleep_for(50ms);
            continue;
        }

        // Setting the total packet size in our memory buffer.
        // Total packet size = Ethernet header size + IPv4 header size + UDP header size + Payload size.

        for (uint16_t i = 0; i < packet_tx_burst_size; ++i) {
            packets[i]->data_len = packets[i]->pkt_len = packet_len;
            packets[i]->ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM;
            packets[i]->l2_len = sizeof(rte_ether_hdr);
            packets[i]->l3_len = sizeof(rte_ipv4_hdr);
        }
        
        // Now our packet(s) are finally prepared. We will now send them using the DPDK API.
        // The DPDK API `rte_eth_tx_burst` will automatically release the memory buffer(s) after tranmission is successful.
        tx_count = 0;
        do {
            tx_count += rte_eth_tx_burst(port_id, queue_id, &packets[tx_count], packet_tx_burst_size - tx_count);
        } while (tx_count < packet_tx_burst_size);
    }

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
    // For example: ./<dpdk_application> --lcores=0 -n 4 -- -s 1 -t 2. `--` will tell the rte_eal_init() that all the DPDK
    // EAL arguments are present before this.  
    // In the above example the DPDK EAL arguments are --lcores and -n. The user arguments are -s and -t. 
    // DPDK EAL argument `--lcores=0` means that this DPDK application will use core 0 to run the main function (main thread). 
    // A DPDK application sets the affinity of execution threads to specific logical cores to achieve performance.
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
        exit(1);
    }

    std::cout << "Total ports detected: " << total_port_count << std::endl;
    
    // Check about the RX/TX offloading support of current ethernet device.
    // A ethernet device from different vendors (Intel, Nvidia, Broadcom etc.) supports different Rx/Tx offloading capabilities.
    // So we first check which Rx/Tx offloading capabilities are supported by our ether device.
    rte_eth_dev_info devInfo;
    if (!check_device_offloading_support(port_ids[0], devInfo)) {
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

    // We must have atleast two logical cores passed as an argument to this DPDK application. The first logical core will get and print the nic statistics.
    // The second logical core will execute the packet transmission routine.
    if (logicalCores.size() != 2) 
    {
        std::cerr << "Two logical cores are required to run this DPDK application. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    // Creating memory pool which contains the memory buffers. A memory buffer is the buffer where DPDK driver will write an 
    // incoming packet. Below memory pool has name "mempool_1" and has 65535 available memory buffer. A single memory buffer 
    // has a size of RTE_MBUF_DEFAULT_BUF_SIZE (2048Bytes + 128Bytes).
    rte_mempool *memory_pool = rte_pktmbuf_pool_create(MEMORY_POOL_NAME.c_str(), MEMORY_POOL_SIZE, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    // Configuring the port (ethernet interface). An ethernet interface can have multiple receive queues and transmit queues. 
    // Currently we are setting up one transmit queue and no receive queue as we are not receiving packets in this tutorial.
    const uint16_t rx_queues = 0;
    const uint16_t tx_queues = 1;

    rte_eth_conf portConf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_NONE
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
            .offloads = (devInfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        }
    };

    // Configure the port (ethernet interface).
    if ((return_val = rte_eth_dev_configure(port_ids[0], rx_queues, tx_queues, &portConf)) != 0) {
        std::cerr << "Unable to configure port. port Id: " << port_ids[0] << " Return code: "  << return_val << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    const int16_t portSocketId = rte_eth_dev_socket_id(port_ids[0]);
    const int16_t coreSocketId = rte_socket_id();

    // Configure the Rx queue(s) of the port.
    for (uint16_t i = 0; i < rx_queues; i++) {
        return_val = rte_eth_rx_queue_setup(port_ids[0], i, 256, ((portSocketId >= 0) ? portSocketId : coreSocketId), nullptr, memory_pool);
        
        if (return_val < 0) {
            std::cerr << "Unable to setup RX queue " << i << " Port Id: " << port_ids[0] << "Return code: " << return_val << std::endl;
            rte_eal_cleanup();
            exit(1);
        }

        std::cout << "Port Id: " << port_ids[0] << " Rx Queue: " << i << " setup successful. Socket id: "   
                  << ((portSocketId >= 0) ? portSocketId : coreSocketId) << std::endl;
    }

    // Configure the Tx queue(s) of the port.
    for (uint16_t i = 0; i < tx_queues; i++) {
        return_val = rte_eth_tx_queue_setup(port_ids[0], i, 1024, ((portSocketId >= 0) ? portSocketId : coreSocketId), nullptr);
        
        if (return_val < 0) {
            std::cerr << "Unable to setup TX queue " << i << " Port Id: " << port_ids[0] << "Return code: " << return_val << std::endl;
            rte_eal_cleanup();
            exit(1);
        }

        std::cout << "Port Id: " << port_ids[0] << " Tx Queue: " << i << " setup successful. Port socket id: " << portSocketId 
                  << " Core socket id: " << coreSocketId << std::endl;
    }

    // Enable promiscuous mode on the port. Not all the DPDK drivers provide the functionality to enable promiscuous mode. So we are going to 
    // ignore the result if the API fails.
    return_val = rte_eth_promiscuous_enable(port_ids[0]);
    if (return_val < 0) {
        std::cout << "Warning: Unable to set the promiscuous mode for port Id: " << port_ids[0] << " Return code: " << return_val << " Ignoring ... " << std::endl;
    }

    // All the configuration is done. Finally starting the port (ethernet interface) so that we can start transmitting the packets.
    return_val = rte_eth_dev_start(port_ids[0]);
    if (return_val < 0) {
        std::cout << "Unable to start port Id: " << port_ids[0] << " Return code: " << return_val << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    std::cout << "Port configuration successful. Port Id: " << port_ids[0] << std::endl;

    // Prepare memory pool.
    if (!prepare_memory_pool()) {
        rte_eth_dev_stop(port_ids[0]);
        rte_eth_dev_close(port_ids[0]);
        rte_eal_cleanup();
        exit(1);
    }

    // Now initiating packet transmission routine on the second logical core id.    
    uint32_t port_and_queue_id = (0 << 16) | 0;   // Port Id: 0, Queue Id: 0 packed in uint32_t.
    if ((return_val = rte_eal_remote_launch(transmit_packets_from_interface, reinterpret_cast<void *>(&port_and_queue_id), logicalCores[1])) != 0) 
    {
        std::cerr << "Unable to launch packet transmission routine on the logical core: %d. Return code: %d" << logicalCores[1] << return_val << std::endl;
        rte_eth_dev_stop(port_ids[0]);
        rte_eth_dev_close(port_ids[0]);
        rte_eal_cleanup();
        exit(1);
    }

    // Logical core 0 will get and print nic statistics.
    get_and_print_nic_statistics(port_ids[0]);

    std::cout << "Exiting DPDK program ... " << std::endl;
    rte_eal_cleanup();
    return 0;
}