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

## 14-ipsec-outbound
This tutorial explains outbound IPsec ESP processing with the DPDK IPsec library (`librte_ipsec`). The application receives cleartext IPv4 traffic on an Ethernet port, encrypts it using a static Security Association (SA), and transmits the ESP frames back on the **same port**.

This tutorial is tested on the **Intel XL710** network adapter. The XL710 (i40e PMD) does not support inline IPsec offload, so encryption runs through a software `cryptodev` device (`crypto_null` PMD). The `crypto_null` driver exercises the full `rte_ipsec` + `cryptodev` pipeline but does not perform real AES-GCM — it is intended for learning the data path.

The application:
1. Creates a virtual `crypto_null0` cryptodev (via EAL `--vdev`).
2. Configures one RX queue and one TX queue on the same port.
3. Installs a static outbound ESP transport-mode SA (fixed SPI).
4. Runs packet I/O on a **worker lcore** (RX → `rte_ipsec_pkt_crypto_prepare` → cryptodev → `rte_ipsec_pkt_process` → TX).
5. The **main lcore** prints statistics once per second.

**Note:** IKE and dynamic SA negotiation are out of scope. Inbound decrypt is not implemented in this tutorial.

To run:
`sudo ./ipsec-outbound -l 0-1 -n 4 --vdev crypto_null0 -- --port <PCI_ADDRESS>`

Example:
`sudo ./ipsec-outbound -l 0-1 -n 4 --vdev crypto_null0 -- --port 0000:04:00.1`

Requires **2 logical cores**: lcore 0 (main/statistics) and lcore 1 (RX/IPsec/TX worker).

Optional PCAP dump of outbound ESP packets (using the same `packet_dumper` approach as tutorial 10):

`sudo ./ipsec-outbound -l 0-1 -n 4 --vdev crypto_null0 -- --port 0000:04:00.1 --dump-pcap`

`--dump-dir <directory>` sets the output directory (default `/tmp`). Files are named `ipsec_outbound_<thread>_<timestamp>_<n>.cap`.

**Test setup example:** Run `packet-generator` on the first port and `ipsec-outbound` on the second port (connected via loopback cable). Cleartext arrives on the IPsec port; encrypted ESP packets are transmitted back on that same port and return over the loopback cable:

`sudo ./packet-generator -l 4-5 -n 4 --file-prefix=packet-gen -b 0000:04:00.1 -- --output-port 0000:04:00.0 --packets-per-second 10000`

`sudo ./ipsec-outbound -l 0-1 -n 4 --file-prefix=ipsec --vdev crypto_null0 -b 0000:04:00.0 -- --port 0000:04:00.1 --dump-pcap`

## 15-rte-flow
This tutorial explains the DPDK Flow API (`rte_flow`). The Flow API lets an application program the NIC hardware classifier to match packet patterns and apply actions (redirect to an RX queue, drop, etc.) inside the NIC (Network Interface Card) before packets reach the CPU.

This tutorial is tested on the **Intel XL710** network adapter (Ethernet Controller XL710 for 40GbE QSFP+, i40e PMD) using the following test environment:

- Two XL710 ports are connected directly with a **loopback cable** (e.g. `0000:04:00.0` and `0000:04:00.1`).
- Tutorial 09 (`packet-generator`) transmits traffic on one port.
- `rte-flow` receives traffic on the other port and verifies hardware redirect, drop, and default-queue behavior.

The application:
1. Configures multiple RX queues on a port.
2. Queries basic flow engine information for the NIC.
3. Validates and installs two hardware flow rules:
   - Match IPv4/UDP destination port (`--redirect-port`) and redirect those packets to `--target-queue`.
   - Match IPv4/UDP destination port (`--drop-port`) and drop those packets in hardware.
4. Polls each RX queue on a dedicated lcore and prints per-queue packet counters so you can observe hardware steering.

Unmatched traffic remains on queue 0. Traffic matching the drop rule should not appear on any queue.

**Note:** Flow item and action support varies by NIC/PMD (for example ixgbe, i40e, mlx5). If `rte_flow_validate` fails, the driver error message indicates which match or action is unsupported on your adapter.

To run:
`sudo ./rte-flow -l 0-2 -n 4 -- --port <PCI_ADDRESS> --num-rx-queues 2 --redirect-port 5000 --drop-port 5001 --target-queue 1`

Example:
`sudo ./rte-flow -l 0-2 -n 4 -- --port 0000:04:00.1 --num-rx-queues 2 --redirect-port 5000 --drop-port 5001 --target-queue 1`

**Test setup example:** Run `packet-generator` on the first port and `rte-flow` on the second port (connected via loopback cable):

`sudo ./packet-generator -l 4-5 -n 4 --file-prefix=packet-gen -b 0000:04:00.1 -- --output-port 0000:04:00.0 --packets-per-second 100000`

`sudo ./rte-flow -l 0-2 -n 4 --file-prefix=rte-flow -b 0000:04:00.0 -- --port 0000:04:00.1 --num-rx-queues 2 --redirect-port 5000 --drop-port 5001 --target-queue 1`

Vary the UDP destination port in test traffic (5000 / 5001 / other) to verify queue redirects, hardware drops, and default-queue behavior. The packet generator cycles UDP destination ports across a range; align `--redirect-port` and `--drop-port` with the ports your generator emits, or adjust the generator accordingly.

## 16-deep-packet-inspection
This tutorial explains **Deep Packet Inspection (DPI)** using DPDK for packet I/O and [nDPI](https://github.com/ntop/nDPI) for application-layer protocol classification. The app receives traffic on one Ethernet port, maintains a bidirectional 5-tuple flow table, feeds each packet to nDPI, and prints per-protocol statistics on the main lcore (passive DPI — no TX / drop / forward).

**Dependency:** install nDPI (tested with 4.14) before building:

```bash
git clone --depth 1 --branch 4.14 https://github.com/ntop/nDPI.git ~/nDPI
cd ~/nDPI && ./autogen.sh && ./configure --prefix=/usr/local && make -j$(nproc) && sudo make install
sudo ldconfig
pkg-config --modversion libndpi
```

**Test environment** (Intel XL710 with a loopback cable between ports):

| Role | PCI address | Driver | Interface example |
|------|-------------|--------|-------------------|
| Replay with `tcpreplay` | `0000:04:00.0` | kernel `i40e` | `enp4s0f0np0` |
| DPI receive | `0000:04:00.1` | `vfio-pci` (DPDK) | — |

Bind **only** the DPI RX port to DPDK (leave the peer on the kernel driver for `tcpreplay`):

```bash
cd ~/dpdk-stable/usertools
sudo ./dpdk-devbind.py -b vfio-pci 0000:04:00.1 --force
sudo ./dpdk-devbind.py -b i40e 0000:04:00.0 --force   # if previously bound to vfio-pci
sudo ./dpdk-devbind.py --status
```

To run:
`sudo ./deep-packet-inspection -l 0-1 -n 4 -- --port <PCI_ADDRESS>`

Example:
`sudo ./deep-packet-inspection -l 0-1 -n 4 --file-prefix=dpi -b 0000:04:00.0 -- --port 0000:04:00.1`

Requires **2 logical cores**: lcore 0 (statistics) and lcore 1 (RX + nDPI worker).

Optional: `--max-flows <N>` (default 65536), `--idle-timeout-sec <N>` (default 60).

**Replay a real-world PCAP** into the kernel peer port (use your own capture file):

```bash
# Bring the kernel interface up
sudo ip link set enp4s0f0np0 up

# In another terminal, with deep-packet-inspection already running:
sudo tcpreplay --intf1=enp4s0f0np0 --mbps=100 /path/to/your.pcap
```

Promiscuous mode is enabled so frames with arbitrary MACs from the PCAP are accepted. Classification often needs several packets per flow before an application name is known (UNKNOWN → DNS/HTTP/TLS/… as nDPI completes detection).

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
