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

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <rte_ether.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <ipsec_util.hpp>
#include <packet_dumper.hpp>

constexpr uint32_t MEMORY_POOL_SIZE = 8191;
constexpr uint16_t NUM_RX_DESCRIPTORS = 512;
constexpr uint16_t NUM_TX_DESCRIPTORS = 512;
constexpr uint16_t BURST_SIZE = 32;
constexpr uint16_t STATISTICS_INTERVAL_SEC = 1;
constexpr uint16_t CRYPTO_DEQUEUE_RETRIES = 10000;
constexpr uint32_t MAX_PCAP_DUMP_FILE_SIZE_MB = 200;

static std::atomic<bool> exit_indicator {false};

static std::atomic<uint64_t> rx_packets_total {0};
static std::atomic<uint64_t> crypto_prepare_total {0};
static std::atomic<uint64_t> crypto_enqueue_total {0};
static std::atomic<uint64_t> crypto_dequeue_total {0};
static std::atomic<uint64_t> ipsec_process_total {0};
static std::atomic<uint64_t> tx_packets_total {0};
static std::atomic<uint64_t> dumped_packets_total {0};
static std::atomic<uint64_t> errors_total {0};

static ipsec_util::IpsecOutboundContext *g_ipsec_ctx {nullptr};
static rte_mempool *memory_pool {nullptr};
static bool g_dump_pcap {false};
static std::string g_dump_pcap_dir {"/tmp"};

void terminate(int /*signal*/)
{
    exit_indicator.store(true, std::memory_order_relaxed);
}

void print_usage(const char *prog_name)
{
    std::cerr << "Usage: " << prog_name
              << " <eal-args> --vdev crypto_null0 -- --port <pci_address>"
              << " [--dump-pcap] [--dump-dir <directory>]" << std::endl;
    std::cerr << "Example: sudo ./ipsec-outbound -l 0-1 -n 4 --vdev crypto_null0 -- --port 0000:04:00.1 --dump-pcap"
              << std::endl;
    std::cerr << "Requires 2 logical cores: main (statistics) + 1 worker (RX/IPsec/TX)." << std::endl;
    std::cerr << "  --dump-pcap           Dump outbound ESP packets to a PCAP file under --dump-dir (default /tmp)." << std::endl;
    std::cerr << "  --dump-dir <directory> Directory for PCAP files (default /tmp)." << std::endl;
}

void prepare_mbuf_for_ipsec(rte_mbuf *packet)
{
    packet->l2_len = sizeof(rte_ether_hdr);
    packet->l3_len = sizeof(rte_ipv4_hdr);
    packet->packet_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
}

bool process_outbound_burst(ipsec_util::IpsecOutboundContext &ctx,
                            rte_mbuf **rx_packets,
                            const uint16_t rx_count,
                            const uint16_t port_id,
                            packet_dumper *pkt_dumper)
{
    rte_crypto_op *crypto_ops[BURST_SIZE] = {nullptr};
    rte_mbuf *tx_packets[BURST_SIZE] = {nullptr};

    for (uint16_t i = 0; i < rx_count; ++i) {
        crypto_ops[i] = rte_crypto_op_alloc(ctx.crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
        if (!crypto_ops[i]) {
            errors_total.fetch_add(rx_count - i, std::memory_order_relaxed);
            for (uint16_t j = 0; j < i; ++j) {
                rte_crypto_op_free(crypto_ops[j]);
            }
            rte_pktmbuf_free_bulk(rx_packets, rx_count);
            return false;
        }
    }

    const uint16_t prepared = rte_ipsec_pkt_crypto_prepare(
        &ctx.ipsec_session, rx_packets, crypto_ops, rx_count);
    if (prepared == 0) {
        errors_total.fetch_add(rx_count, std::memory_order_relaxed);
        for (uint16_t i = 0; i < rx_count; ++i) {
            rte_crypto_op_free(crypto_ops[i]);
        }
        rte_pktmbuf_free_bulk(rx_packets, rx_count);
        return false;
    }

    crypto_prepare_total.fetch_add(prepared, std::memory_order_relaxed);

    if (prepared < rx_count) {
        errors_total.fetch_add(rx_count - prepared, std::memory_order_relaxed);
        for (uint16_t i = prepared; i < rx_count; ++i) {
            rte_crypto_op_free(crypto_ops[i]);
            rte_pktmbuf_free(rx_packets[i]);
        }
    }

    uint16_t enqueued = 0;
    while (enqueued < prepared) {
        const uint16_t count = rte_cryptodev_enqueue_burst(
            ctx.cdev_id, ipsec_util::CRYPTO_QP_ID,
            &crypto_ops[enqueued], prepared - enqueued);
        enqueued += count;
    }
    crypto_enqueue_total.fetch_add(enqueued, std::memory_order_relaxed);

    uint16_t dequeued = 0;
    for (uint16_t retry = 0; dequeued < enqueued && retry < CRYPTO_DEQUEUE_RETRIES; ++retry) {
        dequeued += rte_cryptodev_dequeue_burst(
            ctx.cdev_id, ipsec_util::CRYPTO_QP_ID,
            &crypto_ops[dequeued], enqueued - dequeued);
    }

    if (dequeued != enqueued) {
        errors_total.fetch_add(enqueued - dequeued, std::memory_order_relaxed);
        for (uint16_t i = 0; i < enqueued; ++i) {
            if (crypto_ops[i]) {
                rte_pktmbuf_free(crypto_ops[i]->sym[0].m_src);
                rte_crypto_op_free(crypto_ops[i]);
            }
        }
        return false;
    }

    crypto_dequeue_total.fetch_add(dequeued, std::memory_order_relaxed);

    rte_ipsec_group groups[BURST_SIZE] = {};
    const uint16_t group_count = rte_ipsec_pkt_crypto_group(
        const_cast<const rte_crypto_op **>(reinterpret_cast<rte_crypto_op **>(crypto_ops)),
        tx_packets, groups, dequeued);

    uint16_t tx_total = 0;
    for (uint16_t g = 0; g < group_count; ++g) {
        const uint16_t processed = rte_ipsec_pkt_process(
            static_cast<rte_ipsec_session *>(groups[g].id.ptr),
            groups[g].m, groups[g].cnt);
        ipsec_process_total.fetch_add(processed, std::memory_order_relaxed);

        if (processed > 0) {
            // Dump ESP frames before TX — after rte_eth_tx_burst the driver owns the mbufs.
            if (pkt_dumper != nullptr) {
                for (uint16_t i = 0; i < processed; ++i) {
                    if (pkt_dumper->dump(groups[g].m[i])) {
                        dumped_packets_total.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            const uint16_t sent = rte_eth_tx_burst(port_id, 0, groups[g].m, processed);
            tx_packets_total.fetch_add(sent, std::memory_order_relaxed);
            tx_total += sent;

            if (sent < processed) {
                errors_total.fetch_add(processed - sent, std::memory_order_relaxed);
                for (uint16_t i = sent; i < processed; ++i) {
                    rte_pktmbuf_free(groups[g].m[i]);
                }
            }
        }
    }

    for (uint16_t i = 0; i < dequeued; ++i) {
        rte_crypto_op_free(crypto_ops[i]);
    }

    return tx_total > 0 || prepared > 0;
}

struct OutboundWorkerParams {
    uint16_t port_id {std::numeric_limits<uint16_t>::max()};
};

int ipsec_outbound_worker(void *param)
{
    auto *params = reinterpret_cast<OutboundWorkerParams *>(param);
    const uint16_t port_id = params->port_id;

    std::cout << "Starting IPsec outbound worker on logical core: " << rte_lcore_id()
              << " Port Id: " << port_id << std::endl;

    std::unique_ptr<packet_dumper> pkt_dumper;
    if (g_dump_pcap) {
        pkt_dumper = std::make_unique<packet_dumper>(g_dump_pcap_dir, MAX_PCAP_DUMP_FILE_SIZE_MB);
        std::cout << "Outbound PCAP dump enabled. Directory: " << g_dump_pcap_dir << std::endl;
    }

    rte_mbuf *rx_packets[BURST_SIZE] = {nullptr};
    auto last_flush = std::chrono::steady_clock::now();

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        if (pkt_dumper) {
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush).count()
                >= PACKET_DUMP_FILE_FLUSH_TIMEOUT_MS) {
                pkt_dumper->flush();
                last_flush = now;
            }
        }

        const uint16_t rx_count = rte_eth_rx_burst(port_id, 0, rx_packets, BURST_SIZE);
        if (rx_count == 0) {
            continue;
        }

        rx_packets_total.fetch_add(rx_count, std::memory_order_relaxed);

        for (uint16_t i = 0; i < rx_count; ++i) {
            prepare_mbuf_for_ipsec(rx_packets[i]);
        }

        process_outbound_burst(*g_ipsec_ctx, rx_packets, rx_count, port_id, pkt_dumper.get());
    }

    if (pkt_dumper) {
        pkt_dumper->flush();
    }

    delete params;
    std::cout << "Exiting IPsec outbound worker on logical core: " << rte_lcore_id() << std::endl;
    return 0;
}

void print_statistics_snapshot(const uint16_t port_id)
{
    std::cout << std::endl;
    std::cout << "IPsec Outbound Statistics (port Id: " << port_id << ")" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << " RX packets:          "
              << rx_packets_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Crypto prepared:       "
              << crypto_prepare_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Crypto enqueued:       "
              << crypto_enqueue_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " Crypto dequeued:       "
              << crypto_dequeue_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " IPsec processed:       "
              << ipsec_process_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << " TX packets:            "
              << tx_packets_total.load(std::memory_order_relaxed) << std::endl;
    if (g_dump_pcap) {
        std::cout << " PCAP dumped packets:   "
                  << dumped_packets_total.load(std::memory_order_relaxed) << std::endl;
    }
    std::cout << " Errors:                "
              << errors_total.load(std::memory_order_relaxed) << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
}

void print_statistics(const uint16_t port_id)
{
    std::cout << "Starting statistics routine on logical core: " << rte_lcore_id() << std::endl;

    while (!exit_indicator.load(std::memory_order_relaxed)) {
        print_statistics_snapshot(port_id);
        std::this_thread::sleep_for(std::chrono::seconds(STATISTICS_INTERVAL_SEC));
    }
}

void cleanup(const uint16_t port_id, ipsec_util::IpsecOutboundContext &ipsec_ctx)
{
    if (rte_eth_dev_is_valid_port(port_id)) {
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }

    if (memory_pool != nullptr) {
        rte_mempool_free(memory_pool);
        memory_pool = nullptr;
    }

    ipsec_util::cleanup(ipsec_ctx);
    g_ipsec_ctx = nullptr;
    rte_eal_cleanup();
}

int main(int argc, char **argv)
{
    struct sigaction action;
    std::memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = terminate;
    sigaction(SIGTERM, &action, nullptr);
    sigaction(SIGINT, &action, nullptr);

    std::cout << "Starting DPDK IPsec outbound tutorial ..." << std::endl;

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
        } else if (std::strcmp(argv[i], "--dump-pcap") == 0) {
            g_dump_pcap = true;
        } else if (std::strcmp(argv[i], "--dump-dir") == 0 && (i + 1) < static_cast<uint16_t>(argc)) {
            g_dump_pcap_dir = argv[i + 1];
            g_dump_pcap = true;
        }
    }

    if (port.empty()) {
        print_usage("ipsec-outbound");
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

    constexpr uint16_t num_required_logical_cores = 2;
    if (logical_cores.size() < num_required_logical_cores) {
        std::cerr << "Insufficient logical cores. Required: " << num_required_logical_cores
                  << " (1 main/statistics + 1 RX/IPsec/TX worker). Provided: "
                  << logical_cores.size() << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    ipsec_util::IpsecOutboundContext ipsec_ctx;
    g_ipsec_ctx = &ipsec_ctx;

    if (ipsec_util::init_cryptodev(ipsec_ctx) != 0) {
        cleanup(0, ipsec_ctx);
        exit(1);
    }

    if (ipsec_util::init_outbound_sa(ipsec_ctx) != 0) {
        cleanup(0, ipsec_ctx);
        exit(1);
    }

    uint16_t port_id = std::numeric_limits<uint16_t>::max();
    if (rte_eth_dev_get_port_by_name(port.c_str(), &port_id) != 0) {
        std::cerr << "Unable to get port id for: " << port << std::endl;
        cleanup(port_id, ipsec_ctx);
        exit(1);
    }

    std::cout << "Port: " << port << " detected. Port Id: " << port_id << std::endl;

    memory_pool = rte_pktmbuf_pool_create(
        "mempool_ipsec_outbound", MEMORY_POOL_SIZE, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!memory_pool) {
        std::cerr << "Unable to create packet mbuf pool. " << std::endl;
        cleanup(port_id, ipsec_ctx);
        exit(1);
    }

    const uint16_t rx_queues = 1;
    const uint16_t tx_queues = 1;
    rte_eth_conf port_conf = {
        .rxmode = {.mq_mode = RTE_ETH_MQ_RX_NONE},
        .txmode = {.mq_mode = RTE_ETH_MQ_TX_NONE},
    };

    if (rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf) != 0) {
        std::cerr << "Unable to configure port Id: " << port_id << std::endl;
        cleanup(port_id, ipsec_ctx);
        exit(1);
    }

    const int16_t port_socket_id = rte_eth_dev_socket_id(port_id);
    const int16_t core_socket_id = static_cast<int16_t>(rte_socket_id());

    if (rte_eth_rx_queue_setup(
            port_id, 0, NUM_RX_DESCRIPTORS,
            (port_socket_id >= 0) ? port_socket_id : core_socket_id,
            nullptr, memory_pool) < 0) {
        std::cerr << "Unable to setup RX queue for port Id: " << port_id << std::endl;
        cleanup(port_id, ipsec_ctx);
        exit(1);
    }

    if (rte_eth_tx_queue_setup(
            port_id, 0, NUM_TX_DESCRIPTORS,
            (port_socket_id >= 0) ? port_socket_id : core_socket_id,
            nullptr) < 0) {
        std::cerr << "Unable to setup TX queue for port Id: " << port_id << std::endl;
        cleanup(port_id, ipsec_ctx);
        exit(1);
    }

    return_val = rte_eth_promiscuous_enable(port_id);
    if (return_val != 0) {
        std::cout << "Warning: Unable to enable promiscuous mode on port Id: " << port_id
                  << " Return code: " << return_val << std::endl;
    }

    if (rte_eth_dev_start(port_id) != 0) {
        std::cerr << "Unable to start port Id: " << port_id << std::endl;
        cleanup(port_id, ipsec_ctx);
        exit(1);
    }

    std::cout << "Port configuration successful. RX and TX on port Id: " << port_id << std::endl;
    std::cout << "Worker thread will receives cleartext (plain network packets), applies outbound ESP (encryption) and transmits on same port." << std::endl;

    auto *worker_params = new OutboundWorkerParams;
    worker_params->port_id = port_id;

    if ((return_val = rte_eal_remote_launch(ipsec_outbound_worker, reinterpret_cast<void *>(worker_params), logical_cores[1])) != 0) {
        std::cerr << "Unable to launch IPsec worker on logical core: " << logical_cores[1] << " Return code: " << return_val << std::endl;
        delete worker_params;
        cleanup(port_id, ipsec_ctx);
        exit(1);
    }

    print_statistics(port_id);

    std::cout << "Waiting for logical core " << logical_cores[1] << " to join." << std::endl;
    rte_eal_wait_lcore(logical_cores[1]);

    print_statistics_snapshot(port_id);

    std::cout << "Exiting DPDK IPsec outbound tutorial ..." << std::endl;
    cleanup(port_id, ipsec_ctx);
    return 0;
}
