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
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

static volatile sig_atomic_t exit_indicator = 0;

static rte_ring* ring_buffer = nullptr;

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
                printf("Total packets received: %llu \n", total_rx_packets);
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

    // Lookup for the ring buffer created by a primary application.
    ring_buffer = rte_ring_lookup(ring_buffer_name.c_str());
    if (ring_buffer == nullptr) 
    {
        std::cerr << "Unable to lookup for ring buffer: " << ring_buffer_name.c_str() << " RTE errno: " << rte_strerror(rte_errno);
        rte_eal_cleanup();
        exit(1);
    }

    std::cout << "Ring buffer lookup successful against name: " << ring_buffer_name.c_str() << std::endl;
    process_packets(nullptr);

    std::cout << "Exiting DPDK program ... " << std::endl;
    rte_eal_cleanup();
    return 0;
}