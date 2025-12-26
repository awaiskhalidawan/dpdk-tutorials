# DPDK Tutorials
This repository contains DPDK (https://www.dpdk.org/) tutorials. The tutorials demonstrates the different functionalities and concepts of DPDK library.

## 01-reading-a-packet-from-nic 
This tutorial explains simple steps for beginners to read a packet from NIC interface using DPDK. To execute: `sudo ./reading-a-packet-from-nic --lcores=0 -n 4 --`

## 02-sending-a-packet-from-nic
This tutorial explains simple steps for beginners to transmit a packet from NIC interface using DPDK. To execute: `sudo ./sending-a-packet-from-nic --lcores=0 -n 4 --`

## 03-processing-a-packet
This tutorial explains simple steps for beginners to receive a packet from NIC and share this packet to the processing thread via ring buffer to process it. To execute: `sudo ./processing-a-packet --lcores=0-1 -n 4 --`

## 04-getting-nic-statistics
This tutorial explains simple steps for beginners to get the statistics from NIC. To execute: `sudo ./getting-nic-statistics --lcores=0 -n 4 --`

## 05-ipv4-checksum-calculation-offloading-to-nic
This tutorial explains how to offload Ipv4 checksum calculation to NIC so that our application don't have to compute it. In this way we save computing resources. To execute: `sudo ./ipv4-checksum-calculation-offloading-to-nic --lcores=0 -n 4 --`

## 06-receive-side-scaling
This tutorial explains how to make use of multiple receive queues of NIC (Network Interface Card) using RSS (Receive Side Scaling). To execute: `sudo ./receive-side-scaling --lcores=0-1 -n 4 --`

## 07-telemetry-in-dpdk
This tutorial explains how to use telemetry in DPDK application. It implements a customized telemetry callback function to send specific info to DPDK telemetry client (dpdk-telemetry.py).  

To execute: `sudo ./telemetry-in-dpdk --lcores=0 -n 4 --`. After this, run the dpdk telemetry client `sudo /dpdk-23.11/usertools/dpdk-telemetry.py`. Once it is started, run the command `/dpdk_app/packet_info` to receive specific telemetry information from our DPDK application.

## 08-multiprocess-communication
This tutorial explains how DPDK applications can communicate with each other via shared memory ring buffers. This tutorial implements a DPDK application which can be executed as a primary or a secondary dpdk application.Primary DPDK process sends packets to secondary DPDK process via shared memory ring buffers.  

To execute primary DPDK process: `sudo ./multiprocess-communication --lcores=0@0 -n 4 --proc-type=primary -- ring_buffer_1`. To execute secondary DPDK process: `sudo ./multiprocess-communication --lcores=0@0 -n 4 --proc-type=secondary -- ring_buffer_1`

## 09-packet-generator
This is a DPDK based high speed packet generator. It is tested on Intel XL710 network adapter to send `10gbps (~7mpps, packet size: 214 bytes)` of traffic on one thread using Intel Core-i9 processor on Ubuntu 24 LTS operating system.  

The packet generator application offloads the IP and UDP checksum calculation to hardware (Intel XL710 network adapter) to save the CPU cycles.  

To run the packet generator: `sudo ./packet-generator -l <cores_ids> -n 4 --file-prefix=packet-gen -b <port_id_to_skip> -- --output-port <output_port_id> --packets-per-second <packets_per_second>`.  

For example: `sudo ./packet-generator -l 4-5 -n 4 --file-prefix=packet-gen -b 0000:00:08.0 -- --output-port 0000:00:09.0 --packets-per-second 30000` will run the packet generator using cores `4` and `5`. It will use the port `0000:00:09.0` to send the packets. The packet rate will be `30000` packets per second. The port `0000:00:08.0` will be skipped by DPDK library. This parameter is optional.

## 10-packet-dumper
This is a DPDK based packet dumper. It receives the packets form the port and write it on the pcap files. A user can configure multiple RX queues to enable packet dumping on high data rates.  

To run the packet dumper: `sudo ./packet-dumper -l 0-2 -n 4 -- --input-port 0000:00:08.0 --num-rx-queues 1`. For example: `sudo ./packet-dumper -l 0-2 -n 4 -- --input-port 0000:00:08.0 --num-rx-queues 1` will run the packet dumper using cores `0,1` and `2`. It will use the port `0000:00:08.0` to receive the packets. The number of rx queues will `1`. The output pcap files will be written in `/tmp` folder.

## 11-rss-toeplitz-hash-test
This tutorial explains the functionaly of Toeplitz hash function. The Toeplitz hash function is used by NIC to distribute the packets in RSS (Receive Side Scaling). To run the application: `./rss-toeplitz-hash-test`.

## 12-packet-classification-and-access-control
This tutorial explains the functionaly of DPDK ACL (classification and access control) library. The DPDK ACL library allows the user to classify the packets on the basis of different tuple rules i.e. protocol, source/destination ip, source/destination port.  

## 13-packet-types-check
This tutorial explains how to check the different packet types a ethernet port can classify at hardware level when the packet is received. 
For example: When a packet is received by the port, it is parsed inside the hardware and detected packet types are set in the memory buffer field: `mbuf->packet_type`. This helps to avoid parsing the headers in the software thus saving the CPU cycles.

For example:
1. `(mbuf->packet_type & RTE_PTYPE_L3_IPV4) == RTE_PTYPE_L3_IPV4` means the packet is an IPv4 packet.
2. `(mbuf->packet_type & RTE_PTYPE_L3_IPV4) == RTE_PTYPE_L3_IPV4 && (mbuf->packet_type & RTE_PTYPE_L4_UDP) == RTE_PTYPE_L4_UDP` means the packet is an IPv4 UDP packet.
3. `(mbuf->packet_type & RTE_PTYPE_L3_IPV6) == RTE_PTYPE_L3_IPV6 && (mbuf->packet_type & RTE_PTYPE_L4_TCP) == RTE_PTYPE_L4_TCP` means the packet is an IPv6 TCP packet.

Different NICs supports different packet types. 

To run the application: `sudo ./packet-types-check -l 0 -n 4 -- --port <PCI_ADDRESS>`.

Example: `sudo ./packet-types-check -l 0 -n 4 -- --port 0000:04:00.1`.

## How to build the project
To build the project: <br />
`cd dpdk-tutorials` <br />
`mkdir build` <br />
`cd build` <br />
`cmake -DCMAKE_BUILD_TYPE=Debug ..` <br />
`make` <br />

The binaries will be generated in `bin` folder.

## Support
For any queries or problems feel free to reach at awais.khalid.awan@gmail.com
