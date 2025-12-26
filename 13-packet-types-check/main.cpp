// MIT License
//
// Copyright (c) 2025 Muhammad Awais Khalid
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
#include <cstdint>
#include <limits>
#include <rte_mbuf_ptype.h>
#include <rte_ethdev.h>

void check_supported_packet_types(const int port_id)
{
	int nb_ptypes = rte_eth_dev_get_supported_ptypes(port_id, RTE_PTYPE_ALL_MASK, NULL, 0);
	if (nb_ptypes < 0) {
		std::cerr << "Unable to check supported packet types. Port id: " << port_id << " Return code: " << nb_ptypes << std::endl;
		return;
	}

    if (nb_ptypes == 0) {
        std::cerr << "No packet type supported. Port Id: " << port_id << std::endl;
        return;
    }

	uint32_t ptypes[nb_ptypes];
	nb_ptypes = rte_eth_dev_get_supported_ptypes(port_id, RTE_PTYPE_ALL_MASK, ptypes, nb_ptypes);
	    
    std::cout << "Port id: " << port_id << " supported packet types: " << std::endl;
	for (int i = 0; i < nb_ptypes; ++i) {
        char ptype_name_buffer[100] = {0};
        int ret_val = rte_get_ptype_name(ptypes[i], ptype_name_buffer, sizeof(ptype_name_buffer));
        if (ret_val < 0) {
            std::cerr << "Unable to get packet type name. Packet type: " << ptypes[i] << std::endl;
            continue;
        }

        std::cout << " " << ptype_name_buffer << std::endl;
	}
    std::cout << std::endl;

	return;
}

int main(int argc, char *argv[])
{
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

    std::string port;
    for (uint16_t i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--port") == 0) {
            if ((i + 1) < argc) {
                port = argv[i + 1];
            } else {
                break;
            }
        }
    }

    if (port.empty()) {
        std::cerr << "Port not specified in the command line arguments " << std::endl;
        exit(1);
    }

    // Check whether the input port is detected by the application.
    uint16_t port_id = std::numeric_limits<decltype(port_id)>::max();
    if (rte_eth_dev_get_port_by_name(port.c_str(), &port_id)) {
        std::cerr << "Unable to get port id against port: " << port << std::endl;
        rte_eal_cleanup();
        exit(1);
    }
    
    std::cout << "Port: " << port << " detected by the application. Port id: " << port_id << std::endl;

    std::cout << "Testing supported packet types for port: " << port << std::endl;

    check_supported_packet_types(port_id);

    std::cout << "Exiting ..." << std::endl;

    rte_eal_cleanup();

    return 0;
}