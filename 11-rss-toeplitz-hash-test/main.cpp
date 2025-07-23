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
#include <rte_ip4.h>
#include <rte_thash.h>

// A structure to store the ipv4 src/dest ip, port and layer 3,4 hash values.
struct test_thash_v4
{
    uint32_t dst_ip;
    uint32_t src_ip;
    uint16_t dst_port;
    uint16_t src_port;
    uint32_t hash_l3;
    uint32_t hash_l3l4;
};

// An array to store some random ipv4 src/dest ip, port and their respective layer 3,4 hash values.
struct test_thash_v4 v4_tbl[] = {
    {RTE_IPV4(161, 142, 100, 80), RTE_IPV4(66, 9, 149, 187),
     1766, 2794, 0x323e8fc2, 0x51ccc178},
    {RTE_IPV4(65, 69, 140, 83), RTE_IPV4(199, 92, 111, 2),
     4739, 14230, 0xd718262a, 0xc626b0ea},
    {RTE_IPV4(12, 22, 207, 184), RTE_IPV4(24, 19, 198, 95),
     38024, 12898, 0xd2d0a5de, 0x5c2b394a},
    {RTE_IPV4(209, 142, 163, 6), RTE_IPV4(38, 27, 205, 30),
     2217, 48228, 0x82989176, 0xafc7327f},
    {RTE_IPV4(202, 188, 127, 2), RTE_IPV4(153, 39, 163, 191),
     1303, 44251, 0x5d1809c5, 0x10e828a2},
};

// A default RSS hash key. This key will result different layer 3 and layer 4 hash values.
static uint8_t default_rss_key[] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa};

// A customized RSS hash key. This key will result same layer 3 and layer 4 hash values because
// it doesn't consider port information (All the values are zero after first eight bytes). This
// key shows how a user can control the RSS hash results by just changing the key.
static uint8_t custom_rss_key[] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int main(int argc, char *argv[])
{
    std::cout << "Testing RSS Toeplitz hash algorithm using different keys. " << std::endl;

    rte_ipv4_tuple ipv4_tuple = {0};
    for (uint16_t i = 0; i < RTE_DIM(v4_tbl); ++i)
    {
        ipv4_tuple.src_addr = v4_tbl[i].src_ip;
        ipv4_tuple.dst_addr = v4_tbl[i].dst_ip;
        ipv4_tuple.sport = v4_tbl[i].src_port;
        ipv4_tuple.dport = v4_tbl[i].dst_port;

        // Calculate hash with default RSS key.
        const uint32_t rss_l3_default_key = rte_softrss((uint32_t *)&ipv4_tuple, RTE_THASH_V4_L3_LEN, default_rss_key);
        const uint32_t rss_l3l4_default_key = rte_softrss((uint32_t *)&ipv4_tuple, RTE_THASH_V4_L4_LEN, default_rss_key);

        // Calculate hash with custom RSS key.
        const uint32_t rss_l3_custom_key = rte_softrss((uint32_t *)&ipv4_tuple, RTE_THASH_V4_L3_LEN, custom_rss_key);
        const uint32_t rss_l3l4_custom_key = rte_softrss((uint32_t *)&ipv4_tuple, RTE_THASH_V4_L4_LEN, custom_rss_key);

        std::cout << "-------------------------------------" << std::endl;
        std::cout << "Source ip: " << ipv4_tuple.src_addr << std::endl;
        std::cout << "Destination ip: " << ipv4_tuple.dst_addr << std::endl;
        std::cout << "Source port: " << ipv4_tuple.sport << std::endl;
        std::cout << "Destination port: " << ipv4_tuple.dport << std::endl;
        std::cout << "RSS layer 3 hash (default key): " << rss_l3_default_key << std::endl;
        std::cout << "RSS layer 3,4 hash (default key): " << rss_l3l4_default_key << std::endl;
        std::cout << "RSS layer 3 hash (custom key): " << rss_l3_custom_key << std::endl;
        std::cout << "RSS layer 3,4 hash (custom key): " << rss_l3l4_custom_key << std::endl;
    }

    std::cout << "-------------------------------------" << std::endl;
    std::cout << "Exiting ..." << std::endl;
    return 0;
}