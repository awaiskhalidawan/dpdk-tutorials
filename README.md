# DPDK Tutorials
This repository contains DPDK tutorials.

`1-reading-a-packet-from-nic` : This tutorial explains simple steps for beginners to read a packet from NIC interface using DPDK. To execute: `sudo ./reading-a-packet-from-nic --lcores=0 -n 4 --`

`2-sending-a-packet-from-nic` : This tutorial explains simple steps for beginners to transmit a packet from NIC interface using DPDK. To execute: `sudo ./sending-a-packet-from-nic --lcores=0 -n 4 --`

`3-processing-a-packet` : This tutorial explains simple steps for beginners to receive a packet from NIC and share this packet to the processing thread via ring buffer to process it. To execute: `sudo ./processing-a-packet --lcores=0-1 -n 4 --`

`4-getting-nic-statistics` : This tutorial explains simple steps for beginners to receive a packet from NIC and share this packet to the processing thread via ring buffer to process it. To execute: `sudo ./getting-nic-statistics --lcores=0 -n 4 --`

To build the project: <br />
`mkdir build` <br />
`cd build` <br />
`cmake ..` <br />
`make` <br />

The binaries will be generated in `bin` folder.

For any queries or problems feel free to reach at awais.khalid.awan@gmail.com