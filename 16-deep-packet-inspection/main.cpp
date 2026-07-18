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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <flow_table.hpp>
#include <ndpi_util.hpp>

constexpr uint32_t MEMORY_POOL_SIZE = 8191;
constexpr uint16_t NUM_RX_DESCRIPTORS = 1024;
constexpr uint16_t BURST_SIZE = 32;
constexpr uint16_t STATISTICS_INTERVAL_SEC = 1;
constexpr uint16_t TOP_PROTOCOLS_TO_PRINT = 15;
constexpr uint32_t EXPIRE_CHECK_EVERY_N_PACKETS = 4096;

static std::atomic<bool> exit_indicator {false};

static std::atomic<uint64_t> rx_packets_total {0};
static std::atomic<uint64_t> rx_bytes_total {0};
static std::atomic<uint64_t> classified_packets_total {0};
static std::atomic<uint64_t> unknown_packets_total {0};
static std::atomic<uint64_t> non_ip_packets_total {0};
static std::atomic<uint64_t> flow_reject_total {0};
static std::atomic<uint64_t> active_flows {0};

static std::atomic<uint64_t> protocol_packets[NDPI_MAX_SUPPORTED_PROTOCOLS + 1] {};
static std::atomic<uint64_t> protocol_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + 1] {};

static ndpi_util::NdpiContext *g_ndpi_ctx {nullptr};
static rte_mempool *memory_pool {nullptr};
static uint32_t g_max_flows {DEFAULT_MAX_FLOWS};
static uint32_t g_idle_timeout_sec {DEFAULT_IDLE_TIMEOUT_SEC};

void terminate(int /*signal*/)
{
    exit_indicator.store(true, std::memory_order_relaxed);
}

void print_usage(const char *prog_name)
{
    std::cerr << "Usage: " << prog_name
              << " <eal-args> -- --port <pci_address>"
              << " [--max-flows <N>] [--idle-timeout-sec <N>]" << std::endl;
    std::cerr << "Example: sudo ./deep-packet-inspection -l 0-1 -n 4 -- --port 0000:04:00.1"
              << std::endl;
    std::cerr << "Requires 2 logical cores: main (statistics) + 1 worker (RX + nDPI)." << std::endl;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

bool parse_and_classify(rte_mbuf *packet, FlowTable &flows, uint64_t time_ms)
{
    uint16_t offset = 0;
    if (rte_pktmbuf_data_len(packet) < sizeof(rte_ether_hdr)) {
        return false;
    }

    auto *eth = rte_pktmbuf_mtod(packet, rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    offset = sizeof(rte_ether_hdr);

    // Strip a single VLAN tag if present.
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        if (rte_pktmbuf_data_len(packet) < offset + sizeof(rte_vlan_hdr)) {
            return false;
        }
        auto *vlan = rte_pktmbuf_mtod_offset(packet, rte_vlan_hdr *, offset);
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
        offset += sizeof(rte_vlan_hdr);
    }

    uint8_t l3_version = 0;
    uint8_t l4_proto = 0;
    uint8_t src_ip[16] {};
    uint8_t dst_ip[16] {};
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    const uint8_t *l3_ptr = nullptr;
    uint16_t l3_len = 0;

    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        if (rte_pktmbuf_data_len(packet) < offset + sizeof(rte_ipv4_hdr)) {
            return false;
        }
        auto *ip4 = rte_pktmbuf_mtod_offset(packet, rte_ipv4_hdr *, offset);
        const uint16_t ihl = static_cast<uint16_t>(ip4->ihl) * 4;
        if (ihl < sizeof(rte_ipv4_hdr)) {
            return false;
        }
        l3_version = 4;
        l4_proto = ip4->next_proto_id;
        std::memcpy(src_ip, &ip4->src_addr, 4);
        std::memcpy(dst_ip, &ip4->dst_addr, 4);
        l3_ptr = reinterpret_cast<const uint8_t *>(ip4);
        l3_len = static_cast<uint16_t>(rte_pktmbuf_data_len(packet) - offset);

        const uint16_t l4_offset = offset + ihl;
        if (l4_proto == IPPROTO_TCP && rte_pktmbuf_data_len(packet) >= l4_offset + sizeof(rte_tcp_hdr)) {
            auto *tcp = rte_pktmbuf_mtod_offset(packet, rte_tcp_hdr *, l4_offset);
            src_port = rte_be_to_cpu_16(tcp->src_port);
            dst_port = rte_be_to_cpu_16(tcp->dst_port);
        } else if (l4_proto == IPPROTO_UDP && rte_pktmbuf_data_len(packet) >= l4_offset + sizeof(rte_udp_hdr)) {
            auto *udp = rte_pktmbuf_mtod_offset(packet, rte_udp_hdr *, l4_offset);
            src_port = rte_be_to_cpu_16(udp->src_port);
            dst_port = rte_be_to_cpu_16(udp->dst_port);
        }
    } else if (ether_type == RTE_ETHER_TYPE_IPV6) {
        if (rte_pktmbuf_data_len(packet) < offset + sizeof(rte_ipv6_hdr)) {
            return false;
        }
        auto *ip6 = rte_pktmbuf_mtod_offset(packet, rte_ipv6_hdr *, offset);
        l3_version = 6;
        l4_proto = ip6->proto;
        std::memcpy(src_ip, &ip6->src_addr, 16);
        std::memcpy(dst_ip, &ip6->dst_addr, 16);
        l3_ptr = reinterpret_cast<const uint8_t *>(ip6);
        l3_len = static_cast<uint16_t>(rte_pktmbuf_data_len(packet) - offset);

        const uint16_t l4_offset = offset + sizeof(rte_ipv6_hdr);
        if (l4_proto == IPPROTO_TCP && rte_pktmbuf_data_len(packet) >= l4_offset + sizeof(rte_tcp_hdr)) {
            auto *tcp = rte_pktmbuf_mtod_offset(packet, rte_tcp_hdr *, l4_offset);
            src_port = rte_be_to_cpu_16(tcp->src_port);
            dst_port = rte_be_to_cpu_16(tcp->dst_port);
        } else if (l4_proto == IPPROTO_UDP && rte_pktmbuf_data_len(packet) >= l4_offset + sizeof(rte_udp_hdr)) {
            auto *udp = rte_pktmbuf_mtod_offset(packet, rte_udp_hdr *, l4_offset);
            src_port = rte_be_to_cpu_16(udp->src_port);
            dst_port = rte_be_to_cpu_16(udp->dst_port);
        }
    } else {
        non_ip_packets_total.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const FlowKey key = make_flow_key(l3_version, l4_proto, src_ip, src_port, dst_ip, dst_port);
    bool created = false;
    bool rejected = false;
    FlowEntry *entry = flows.get_or_create(key, time_ms, created, rejected);
    if (!entry) {
        if (rejected) {
            flow_reject_total.fetch_add(1, std::memory_order_relaxed);
        }
        return false;
    }

    if (created) {
        active_flows.fetch_add(1, std::memory_order_relaxed);
    }

    entry->packets += 1;
    entry->bytes += packet->pkt_len;

    entry->detected = ndpi_util::process_packet(*g_ndpi_ctx, entry->ndpi_flow, l3_ptr, l3_len, time_ms);

    if (!entry->detection_completed && ndpi_is_protocol_detected(entry->detected) != 0) {
        if (entry->detected.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN
            || entry->detected.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            entry->detection_completed = true;
        }
    }

    const uint16_t proto_id = ndpi_util::preferred_protocol_id(entry->detected);
    if (proto_id <= NDPI_MAX_SUPPORTED_PROTOCOLS) {
        protocol_packets[proto_id].fetch_add(1, std::memory_order_relaxed);
        protocol_bytes[proto_id].fetch_add(packet->pkt_len, std::memory_order_relaxed);
    }

    if (proto_id == NDPI_PROTOCOL_UNKNOWN) {
        unknown_packets_total.fetch_add(1, std::memory_order_relaxed);
    } else {
        classified_packets_total.fetch_add(1, std::memory_order_relaxed);
    }

    return true;
}

struct DpiWorkerParams {
    uint16_t port_id {std::numeric_limits<uint16_t>::max()};
};

int dpi_worker(void *param)
{
    auto *params = reinterpret_cast<DpiWorkerParams *>(param);
    const uint16_t port_id = params->port_id;

    std::cout << "Starting DPI worker on logical core: " << rte_lcore_id()
              << " Port Id: " << port_id << std::endl;

    FlowTable flows(g_max_flows, g_idle_timeout_sec);
    rte_mbuf *rx_packets[BURST_SIZE] = {nullptr};
    uint64_t packets_since_expire = 0;

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        const uint16_t rx_count = rte_eth_rx_burst(port_id, 0, rx_packets, BURST_SIZE);
        if (rx_count == 0) {
            continue;
        }

        const uint64_t time_ms = now_ms();
        uint64_t burst_bytes = 0;
        for (uint16_t i = 0; i < rx_count; ++i) {
            burst_bytes += rx_packets[i]->pkt_len;
            parse_and_classify(rx_packets[i], flows, time_ms);
        }

        rx_packets_total.fetch_add(rx_count, std::memory_order_relaxed);
        rx_bytes_total.fetch_add(burst_bytes, std::memory_order_relaxed);
        packets_since_expire += rx_count;

        rte_pktmbuf_free_bulk(rx_packets, rx_count);

        if (packets_since_expire >= EXPIRE_CHECK_EVERY_N_PACKETS) {
            const uint32_t removed = flows.expire_idle(time_ms);
            if (removed > 0) {
                active_flows.fetch_sub(removed, std::memory_order_relaxed);
            }
            packets_since_expire = 0;
            active_flows.store(flows.size(), std::memory_order_relaxed);
        }
    }

    active_flows.store(flows.size(), std::memory_order_relaxed);
    delete params;
    std::cout << "Exiting DPI worker on logical core: " << rte_lcore_id() << std::endl;
    return 0;
}

void print_statistics_snapshot()
{
    std::vector<std::pair<uint16_t, uint64_t>> ranked;
    ranked.reserve(TOP_PROTOCOLS_TO_PRINT * 2);
    for (uint16_t id = 0; id <= NDPI_MAX_SUPPORTED_PROTOCOLS; ++id) {
        const uint64_t count = protocol_packets[id].load(std::memory_order_relaxed);
        if (count > 0) {
            ranked.emplace_back(id, count);
        }
    }

    std::sort(ranked.begin(), ranked.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    const uint64_t rx_pkts = rx_packets_total.load(std::memory_order_relaxed);
    const uint64_t rx_bytes = rx_bytes_total.load(std::memory_order_relaxed);

    std::cout << std::endl;
    std::cout << "Deep Packet Inspection Statistics" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << " RX packets:            " << rx_pkts << std::endl;
    std::cout << " RX bytes:              " << rx_bytes << std::endl;
    std::cout << " Active flows:          " << active_flows.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Classified packets:    " << classified_packets_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Unknown packets:       " << unknown_packets_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Non-IP packets:        " << non_ip_packets_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Flow table rejects:    " << flow_reject_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Top protocols (by packets):" << std::endl;

    const size_t limit = std::min<size_t>(TOP_PROTOCOLS_TO_PRINT, ranked.size());
    for (size_t i = 0; i < limit; ++i) {
        const uint16_t id = ranked[i].first;
        const uint64_t pkts = ranked[i].second;
        const uint64_t bytes = protocol_bytes[id].load(std::memory_order_relaxed);
        std::cout << "   " << (i + 1) << ". "
                  << ndpi_util::protocol_name(*g_ndpi_ctx, id)
                  << "  packets=" << pkts
                  << "  bytes=" << bytes << std::endl;
    }
    std::cout << "----------------------------------------------" << std::endl;
}

void print_statistics()
{
    std::cout << "Starting statistics routine on logical core: " << rte_lcore_id() << std::endl;
    while (!exit_indicator.load(std::memory_order_relaxed)) {
        print_statistics_snapshot();
        std::this_thread::sleep_for(std::chrono::seconds(STATISTICS_INTERVAL_SEC));
    }
}

void cleanup(const uint16_t port_id, ndpi_util::NdpiContext &ndpi_ctx)
{
    if (rte_eth_dev_is_valid_port(port_id)) {
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }

    if (memory_pool != nullptr) {
        rte_mempool_free(memory_pool);
        memory_pool = nullptr;
    }

    ndpi_util::cleanup(ndpi_ctx);
    g_ndpi_ctx = nullptr;
    rte_eal_cleanup();
}

int main(int argc, char **argv)
{
    struct sigaction action {};
    action.sa_handler = terminate;
    sigaction(SIGTERM, &action, nullptr);
    sigaction(SIGINT, &action, nullptr);

    std::cout << "Starting DPDK Deep Packet Inspection tutorial (nDPI) ..." << std::endl;

    int32_t return_val = rte_eal_init(argc, argv);
    if (return_val < 0) {
        std::cerr << "Unable to initialize DPDK EAL. Error: " << rte_errno << std::endl;
        exit(1);
    }
    argc -= return_val;
    argv += return_val;

    std::string port;
    for (uint16_t i = 0; i < static_cast<uint16_t>(argc); ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && (i + 1) < static_cast<uint16_t>(argc)) {
            port = argv[i + 1];
        } else if (std::strcmp(argv[i], "--max-flows") == 0 && (i + 1) < static_cast<uint16_t>(argc)) {
            g_max_flows = static_cast<uint32_t>(std::strtoul(argv[i + 1], nullptr, 10));
        } else if (std::strcmp(argv[i], "--idle-timeout-sec") == 0 && (i + 1) < static_cast<uint16_t>(argc)) {
            g_idle_timeout_sec = static_cast<uint32_t>(std::strtoul(argv[i + 1], nullptr, 10));
        }
    }

    if (port.empty()) {
        print_usage("deep-packet-inspection");
        rte_eal_cleanup();
        exit(1);
    }

    uint16_t lcore_id = 0;
    std::vector<uint16_t> logical_cores;
    std::cout << "Logical cores ids (CPU ids): ";
    RTE_LCORE_FOREACH(lcore_id) {
        logical_cores.push_back(lcore_id);
        std::cout << lcore_id << " ";
    }
    std::cout << std::endl;

    if (logical_cores.size() < 2) {
        std::cerr << "Insufficient logical cores. Required: 2 (1 stats + 1 DPI worker). Provided: "
                  << logical_cores.size() << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    ndpi_util::NdpiContext ndpi_ctx;
    g_ndpi_ctx = &ndpi_ctx;
    if (ndpi_util::init(ndpi_ctx) != 0) {
        cleanup(0, ndpi_ctx);
        exit(1);
    }

    uint16_t port_id = std::numeric_limits<uint16_t>::max();
    if (rte_eth_dev_get_port_by_name(port.c_str(), &port_id) != 0) {
        std::cerr << "Unable to get port id for: " << port << std::endl;
        cleanup(port_id, ndpi_ctx);
        exit(1);
    }
    std::cout << "Port: " << port << " detected. Port Id: " << port_id << std::endl;

    memory_pool = rte_pktmbuf_pool_create(
        "mempool_dpi", MEMORY_POOL_SIZE, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!memory_pool) {
        std::cerr << "Unable to create packet mbuf pool." << std::endl;
        cleanup(port_id, ndpi_ctx);
        exit(1);
    }

    rte_eth_conf port_conf = {
        .rxmode = {.mq_mode = RTE_ETH_MQ_RX_NONE},
        .txmode = {.mq_mode = RTE_ETH_MQ_TX_NONE},
    };

    if (rte_eth_dev_configure(port_id, 1, 0, &port_conf) != 0) {
        std::cerr << "Unable to configure port Id: " << port_id << std::endl;
        cleanup(port_id, ndpi_ctx);
        exit(1);
    }

    const int16_t port_socket_id = rte_eth_dev_socket_id(port_id);
    const int16_t core_socket_id = static_cast<int16_t>(rte_socket_id());

    if (rte_eth_rx_queue_setup(port_id, 0, NUM_RX_DESCRIPTORS,
                               (port_socket_id >= 0) ? port_socket_id : core_socket_id,
                               nullptr, memory_pool) < 0) {
        std::cerr << "Unable to setup RX queue for port Id: " << port_id << std::endl;
        cleanup(port_id, ndpi_ctx);
        exit(1);
    }

    return_val = rte_eth_promiscuous_enable(port_id);
    if (return_val != 0) {
        std::cout << "Warning: Unable to enable promiscuous mode on port Id: " << port_id
                  << " Return code: " << return_val << std::endl;
    }

    if (rte_eth_dev_start(port_id) != 0) {
        std::cerr << "Unable to start port Id: " << port_id << std::endl;
        cleanup(port_id, ndpi_ctx);
        exit(1);
    }

    std::cout << "Port configuration successful. Passive DPI on port Id: " << port_id << std::endl;
    std::cout << "Replay traffic into the peer port with tcpreplay (kernel driver)." << std::endl;

    auto *worker_params = new DpiWorkerParams;
    worker_params->port_id = port_id;

    if ((return_val = rte_eal_remote_launch(dpi_worker, worker_params, logical_cores[1])) != 0) {
        std::cerr << "Unable to launch DPI worker on logical core: " << logical_cores[1]
                  << " Return code: " << return_val << std::endl;
        delete worker_params;
        cleanup(port_id, ndpi_ctx);
        exit(1);
    }

    print_statistics();

    std::cout << "Waiting for logical core " << logical_cores[1] << " to join." << std::endl;
    rte_eal_wait_lcore(logical_cores[1]);

    print_statistics_snapshot();
    std::cout << "Exiting DPDK Deep Packet Inspection tutorial ..." << std::endl;
    cleanup(port_id, ndpi_ctx);
    return 0;
}
