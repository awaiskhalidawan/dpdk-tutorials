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
#include <ctime>
#include <vector>
#include <cstring>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

static volatile sig_atomic_t exit_indicator = 0;

static rte_ring *ring_buffer = {nullptr};

static rte_mempool *memory_buffer_pool {nullptr};

static uint64_t timestamp_dynfield_offset = 0;

void terminate(int signal) 
{
    exit_indicator = 1;
}

std::string get_current_data_time()
{
    // Example of the very popular RFC 3339 format UTC time
    std::time_t time = std::time({});
    char timeString[std::size("yyyy-mm-ddThh:mm:ssZ")];
    std::strftime(std::data(timeString), std::size(timeString),
                  "%FT%TZ", std::gmtime(&time));
    return timeString;
}

int generate_packets(void *params)
{
    uint8_t  tx_count = 0;
    uint64_t total_tx_packets = 0;

    // We will print the logical core id (CPU id) on which this thread is going to be executed. rte_lcore_id() function will
    // return the current logical core id (CPU id). 
    std::cout << "Starting packet generation routine. Logical core id (CPU id): " << rte_lcore_id() << std::endl;

    // Now continuously generate the packets and enqueue it in the ring buffer.
    while (!exit_indicator) {        
        using namespace std::literals;
        std::this_thread::sleep_for(10ms);
        
        // Allocate a new memory buffer (packet) from the memory buffer pool.
        rte_mbuf *const packet = rte_pktmbuf_alloc(memory_buffer_pool);
        if (!packet) {
            std::cerr << "Unable to allocate memory buffer. " << std::endl;            
            continue;
        }

        // Timestamp the memory buffer (packet). The timestamp will be written in the head room of the memory buffer. 
        // Head room is the memory area before actual data room.
        static timespec ts {0};
        clock_gettime(CLOCK_REALTIME, &ts);
        *(RTE_MBUF_DYNFIELD(packet, timestamp_dynfield_offset, uint64_t *)) = ((ts.tv_sec * 1000000000L) + ts.tv_nsec);

        // Filling some data in the packet.
        static const char data[] = "A quick brown fox jumps over the lazy dog."; 
        uint8_t *const data_ptr = rte_pktmbuf_mtod(packet, uint8_t*);
        std::memcpy(data_ptr, data, sizeof(data));
        packet->data_len = sizeof(data);

        // Enqueuing the packet in the ring buffer.
        if (!rte_ring_enqueue(ring_buffer, packet)) {
            total_tx_packets++;
            if (!(total_tx_packets % 100)) {
                std::cout << "Successfully enqueued packet(s) in the ring buffer. total packet: " << total_tx_packets << std::endl; 
            }
        } else {
            std::cerr << "Unable to enqueue packet in the ring buffer. Space is full. " << std::endl;
            rte_pktmbuf_free(packet);
        }
    }

    std::cout << "Total packets generated: " << total_tx_packets << std::endl;    
    std::cout << "Exiting packet generation routine. " << std::endl;
    return 0;
}

int process_packets(void *params)
{
    rte_mbuf* rx_packets[32];
    uint8_t rx_count = 0;
    uint64_t total_rx_packets = 0;
    uint64_t lastTimestamp = 0;

    // We will print the logical core id (CPU id) on which this thread is going to be executed. rte_lcore_id() function will
    // return the current logical core id (CPU id). 
    std::cout << "Starting packet processing routine. Logical core id (CPU id): " << rte_lcore_id() << std::endl;

    // Now continuously monitor the ring buffer for any incoming packets. 
    while (!exit_indicator) {

        // Check for any incoming packets in the ring buffer. We try to dequeue max 32 packets at max at a time.
        rx_count = rte_ring_dequeue_burst(ring_buffer, reinterpret_cast<void **>(rx_packets), 1, nullptr);

        if (!rx_count) {
            // No packets are present in ring buffer. Check again.
            using namespace std::literals;
            std::this_thread::sleep_for(50us);
            continue;
        }

        // Packets received. Now we will process them.
        for (uint8_t i = 0; i < rx_count; i++) {
            total_rx_packets++;
            rte_mbuf *const packet = rx_packets[i];

            // Get the timestamp of the received memory buffer (packet).
            const uint64_t timestamp = *(RTE_MBUF_DYNFIELD(packet, timestamp_dynfield_offset, uint64_t *));

            if (!(total_rx_packets % 100)) {
                printf("Total packets received: %lu \n", total_rx_packets);
                uint8_t *data = rte_pktmbuf_mtod(packet, uint8_t*);
                printf("packet data: %s \n", data); 
            }

            if (timestamp < lastTimestamp) {
                std::cerr << get_current_data_time() << " The received timestamp is less than last time stamp. " << lastTimestamp << ":" << timestamp 
                << ":" << packet->data_len << ":" << packet << std::endl;
            }            

            lastTimestamp = timestamp;
            rte_pktmbuf_free(packet);
        }
    }

    std::cout << "Total packets received: " << total_rx_packets << std::endl;    
    std::cout << "Exiting packet processing routine. " << std::endl;
    return 0;
}

static const struct rte_mbuf_dynfield tsDynfieldDesc = {
  .name = "dynfield_ts",
  .size = sizeof(uint64_t),
  .align = __alignof__(uint64_t),
};

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

    if (argc < 2) {
        std::cerr << "ring buffer name not provided in command line arguments. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    std::string ring_buffer_name = argv[1];
    if (ring_buffer_name.empty()) {
        std::cerr << "ring buffer name is empty. " << std::endl;
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

    // We must have atleast one logical cores passed as an argument to this DPDK application.
    if (logicalCores.size() != 1) 
    {
        std::cerr << "One logical core is required to run this DPDK application. " << std::endl;
        rte_eal_cleanup();
        exit(1);
    }

    // Register a timestamp dynamic field. 
    timestamp_dynfield_offset = rte_mbuf_dynfield_register(&tsDynfieldDesc);
    if (timestamp_dynfield_offset < 0) {
        std::cerr << "Cannot register mbuf dynfield: dynfield_ts. RTE Errno: " << rte_strerror(rte_errno) << std::endl;
        rte_eal_cleanup();
        exit(1);
    } else {
        std::cout << "Timestamp dynamic field offset: " << timestamp_dynfield_offset << std::endl;
    }

    // Find the process type of current process. Whether its a primary or secondary.
	const rte_proc_type_t proc_type = rte_eal_process_type();

    if (proc_type == RTE_PROC_PRIMARY)
    {
        // Primary process with create the memory buffer pool, create the ring buffer and generate packets.
        // Create a new pool of memory buffers.
        memory_buffer_pool = rte_pktmbuf_pool_create("memory_buffer_pool_1",     // Name of memory buffer pool.
                                                     2048,                       // Size of memory buffer pool. (2048 - 1 = 2047)
                                                     RTE_MEMPOOL_CACHE_MAX_SIZE, // Mempool cache size.
                                                     0,                          // Size of private area of memory buffer.
                                                     RTE_MBUF_DEFAULT_BUF_SIZE,  // Size of memory buffer.
                                                     rte_socket_id());           // Socket on which memory buffer is created.

        if (!memory_buffer_pool) {
            std::cerr << "Unable to create a new memory buffer pool. rte errno: " << rte_strerror(rte_errno);
            rte_eal_cleanup();
            exit(1);
        }

        // Lookup for the ring buffer created by a primary application.
        ring_buffer = rte_ring_create(ring_buffer_name.c_str(),         // Name of ring buffer.
                                      512,                              // Max size of ring buffer. (512 - 1 = 511 elements)
                                      rte_socket_id(),                  // Socket on which ring buffer will be created.
                                      (RING_F_SP_ENQ | RING_F_SC_DEQ)); // Ring buffer type is Single producer / Single consumer.

        if (!ring_buffer) {
            std::cerr << "Unable to create ring buffer: " << ring_buffer_name.c_str() << " RTE errno: " << rte_strerror(rte_errno);
            rte_eal_cleanup();
            exit(1);
        }

        std::cout << "Ring buffer creation successful against name: " << ring_buffer_name.c_str() << std::endl;
        // Start packet generation routine.
        generate_packets(nullptr);
        using namespace std::literals;
        std::this_thread::sleep_for(500ms);
        rte_ring_free(ring_buffer);
    } else if (proc_type == RTE_PROC_SECONDARY) {
        // Primary process with look up for the ring buffer and receive the packets generated by primary DPDK application.
        // Lookup for the ring buffer created by a primary application.
        ring_buffer = rte_ring_lookup(ring_buffer_name.c_str());
        if (ring_buffer == nullptr)
        {
            std::cerr << "Unable to lookup for ring buffer: " << ring_buffer_name.c_str() << " RTE errno: " << rte_strerror(rte_errno);
            rte_eal_cleanup();
            exit(1);
        }

        std::cout << "Ring buffer lookup successful against name: " << ring_buffer_name.c_str() << std::endl;

        // Start receiving and processing the packets.
        process_packets(nullptr);
    }

    std::cout << "Exiting DPDK program ... " << std::endl;    
    rte_eal_cleanup();
    return 0;
}