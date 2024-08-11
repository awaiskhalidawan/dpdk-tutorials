# DPDK Tutorials
This repository contains DPDK tutorials.

`1-reading-a-packet-from-nic` : This tutorial explains simple steps for beginners to read a packet from NIC interface using DPDK. To execute: `sudo ./reading-a-packet-from-nic --lcores=0 -n 4 --`

`2-sending-a-packet-from-nic` : This tutorial explains simple steps for beginners to transmit a packet from NIC interface using DPDK. To execute: `sudo ./sending-a-packet-from-nic --lcores=0 -n 4 --`

`3-processing-a-packet` : This tutorial explains simple steps for beginners to receive a packet from NIC and share this packet to the processing thread via ring buffer to process it. To execute: `sudo ./processing-a-packet --lcores=0-1 -n 4 --`

`4-getting-nic-statistics` : This tutorial explains simple steps for beginners to get the statistics from NIC. To execute: `sudo ./getting-nic-statistics --lcores=0 -n 4 --`

`5-ipv4-checksum-calculation-offloading-to-nic` : This tutorial explains how to offload Ipv4 checksum calculation to NIC so that our application don't have to compute it. In this way we save computing resources. To execute: `sudo ./ipv4-checksum-calculation-offloading-to-nic --lcores=0 -n 4 --`

`6-receive-side-scaling` : This tutorial explains how to make use of multiple receive queues of NIC (Network Interface Card) using RSS (Receive Side Scaling). To execute: `sudo ./receive-side-scaling --lcores=0-1 -n 4 --`

`7-telemetry-in-dpdk` : This tutorial explains how to use telemetry in DPDK application. It implements a customized telemetry callback function to send specific info to DPDK telemetry client (dpdk-telemetry.py). To execute: `sudo ./telemetry-in-dpdk --lcores=0 -n 4 --`. After this, run the dpdk telemetry client `sudo /dpdk-23.11/usertools/dpdk-telemetry.py`. Once it is started, run the command `/dpdk_app/packet_info` to receive specific telemetry information from our DPDK application.

`8-multiprocess-communication` : This tutorial explains how to DPDK applications can communicate with each other via shared memory ring buffers. This tutorial implements a DPDK application which can be executed as a primary or a secondary dpdk application.Primary DPDK process sends packets to secondary DPDK process via shared memory ring buffers. To execute primary DPDK process: `sudo ./multiprocess-communication --lcores=0@0 -n 4 --proc-type=primary -- ring_buffer_1`. To execute secondary DPDK process: `sudo ./multiprocess-communication --lcores=0@0 -n 4 --proc-type=secondary -- ring_buffer_1`

To build the project: <br />
`mkdir build` <br />
`cd build` <br />
`cmake ..` <br />
`make` <br />

The binaries will be generated in `bin` folder.

For any queries or problems feel free to reach at awais.khalid.awan@gmail.com