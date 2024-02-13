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

static volatile sig_atomic_t exit_indicator = 0;

void terminate(int signal) 
{
    exit_indicator = 1;
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
    // DPDK EAL argument `-n 4` means that this DPDK application 4 memory channels. 
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
        return 1;
    }

    std::cout << "Total ports detected: " << total_port_count << std::endl;

    // Creating memory pool which contains the memory buffers. A memory buffer is the buffer where DPDK driver will write an 
    // incoming packet. Below memory pool has name "mempool_1" and has 1023 available memory buffer. A single memory buffer 
    // has a size of RTE_MBUF_DEFAULT_BUF_SIZE (2048Bytes + 128Bytes).
    rte_mempool *memory_pool = rte_pktmbuf_pool_create("mempool_1", 1023, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    // Configuring the port (ethernet interface). An ethernet interface can have multiple receive queues and transmit queues. 
    // Currently we are setting up one transmit queue and no receive queue as we are not receiving packets in this tutorial.
    const uint16_t rx_queues = 0;
    const uint16_t tx_queues = 1;

    rte_eth_conf portConf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_NONE
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE
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
        return_val = rte_eth_tx_queue_setup(port_ids[0], i, 256, ((portSocketId >= 0) ? portSocketId : coreSocketId), nullptr);
        
        if (return_val < 0) {
            std::cerr << "Unable to setup TX queue " << i << " Port Id: " << port_ids[0] << "Return code: " << return_val << std::endl;
            rte_eal_cleanup();
            exit(1);
        }

        std::cout << "Port Id: " << port_ids[0] << " Tx Queue: " << i << " setup successful. Socket id: "   
                  << ((portSocketId >= 0) ? portSocketId : coreSocketId) << std::endl;
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

    std::cout << "Starting packet tranmission on the ethernet port ... " << std::endl;

    uint64_t transmitted_packet_count = 0;

    // Now we go into a loop to continously transmit the packets on the port (ethernet interface).
    while (!exit_indicator) {

        // Get a memory buffer from our memory pool. On this memory buffer we will write our packet data.
        rte_mbuf *packet = nullptr;
        if (rte_mempool_get(memory_pool, reinterpret_cast<void **>(&packet)) != 0) {
            std::cout << "Error: Unable to get memory buffer from memory pool. " << std::endl;
            using namespace std::literals;
            std::this_thread::sleep_for(100ms);
            continue;
        }

        // We have successfully got the memory buffer. Now we will write the packet data. A memory buffer in DPDK is divided 
        // into parts i.e. Head room memory area, main memory area and tail room memory area. The details are available at:
        // https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html
        // We will get a pointer to the main memory area of our memory buffer and write packet info.
        uint8_t *data = rte_pktmbuf_mtod(packet, uint8_t *);

        // Setting Ethernet header information (Source MAC, Destination MAC, Ethernet type).
        rte_ether_hdr *const eth_hdr = reinterpret_cast<rte_ether_hdr *>(data);
        eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        const uint8_t src_mac_addr[6] = {0x12, 0x45, 0xAB, 0xCD, 0x78, 0x21};
        memcpy(eth_hdr->src_addr.addr_bytes, src_mac_addr, sizeof(src_mac_addr));

        const uint8_t dst_mac_addr[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xAB, 0x12};
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

        const uint8_t src_ip_addr[4] = {1, 2, 3, 4};                
        memcpy(&ipv4_hdr->src_addr, src_ip_addr, sizeof(src_ip_addr));      // Setting source ip address = 1.2.3.4

        const uint8_t dest_ip_addr[4] = {4, 3, 2, 1};
        memcpy(&ipv4_hdr->dst_addr, dest_ip_addr, sizeof(dest_ip_addr));    // Setting destination ip address = 4.3.2.1

        ipv4_hdr->hdr_checksum = 0;
        ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);      // Calculating and setting IPv4 checksum in IPv4 header.

        // Setting UDP header information.
        rte_udp_hdr *const udp_hdr = reinterpret_cast<rte_udp_hdr *>(data + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr));
        udp_hdr->dst_port = rte_cpu_to_be_16(5000);     // Setting destination port = 5000;
        udp_hdr->src_port = rte_cpu_to_be_16(10000);    // Setting source port = 10000;
        udp_hdr->dgram_len = rte_cpu_to_be_16(180);     // Setting datagram length = 180;
        udp_hdr->dgram_cksum = 0;                       // Setting checksum = 0;

        // Setting data in the UDP payload
        uint8_t *payload = data + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr);
        memset(payload, 0, 172);
        const char sample_data[] = {"This is a sample data generated by a DPDK application ..."};
        memcpy(payload, sample_data, sizeof(sample_data));

        // Setting the total packet size in our memory buffer.
        // Total packet size = Ethernet header size + IPv4 header size + UDP header size + Payload size.
        packet->data_len = packet->pkt_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + 172;

        // Now our packet is finally prepared. We will now send it using the DPDK API.
        // The DPDK API `rte_eth_tx_burst` will automatically release the memory buffer after tranmission is successful.
        const uint16_t tx_packets = rte_eth_tx_burst(port_ids[0], 0, &packet, 1);
        if (tx_packets == 0) {
            std::cout << "Unable to transmit the packet. " << std::endl;
            rte_pktmbuf_free(packet);   // As the packet is not transmitted, we need to free the memory buffer by our self.
        } else {
            transmitted_packet_count += tx_packets;
            std::cout << "Packet transmitted successfully ... (" << transmitted_packet_count << ")" << std::endl;
        }

        using namespace std::literals;
        std::this_thread::sleep_for(200ms);
    }

    std::cout << "Exiting DPDK program ... " << std::endl;
    rte_eal_cleanup();
    return 0;
}