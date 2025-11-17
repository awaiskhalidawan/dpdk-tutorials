#pragma once
#include <pcap/pcap.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <rte_mbuf.h>

constexpr uint32_t PACKET_DUMP_FILE_FLUSH_TIMEOUT_MS = 5000;

class packet_dumper
{
private:
    pcap_t* pcap_handler {nullptr};
    pcap_dumper_t *dump_handler {nullptr};
    std::string dump_pcap_dir {"/tmp"};
    uint32_t max_packet_dump_file_size_mb {100};
    int32_t packet_timestamp_dynfield_offset {-1};
    uint64_t file_counter {0};

    bool createPacketDumpFile();

public:
    packet_dumper() = delete;
    packet_dumper(const packet_dumper&) = delete;
    packet_dumper(packet_dumper&&) = delete;
    packet_dumper& operator=(const packet_dumper&) = delete;
    packet_dumper& operator=(packet_dumper&&) = delete;
    packet_dumper(const std::string& dump_pcap_directory, const uint32_t max_packet_dump_file_size_mb = 100, const int32_t packet_timestamp_dynfield_offset = -1);
    ~packet_dumper();

    bool dump(rte_mbuf* packet);
    void flush();
};

packet_dumper::packet_dumper(const std::string& dump_pcap_directory, const uint32_t max_packet_dump_file_size_mb, const int32_t packet_timestamp_dynfield_offset)
{
    if (std::filesystem::exists(dump_pcap_directory) && std::filesystem::is_directory(dump_pcap_directory)) {
        this->dump_pcap_dir = dump_pcap_directory;
    } else {        
        std::cout << "Dump pcap directory: " << dump_pcap_directory << " does not exists. Keeping default dump pcap directory path: " << dump_pcap_dir << std::endl;
    }

    if (max_packet_dump_file_size_mb > 50 && max_packet_dump_file_size_mb <= 1024) {
        this->max_packet_dump_file_size_mb = max_packet_dump_file_size_mb;
    } else {
        std::cout << "Invalid max packet dump file size: " << max_packet_dump_file_size_mb << ". Keeping default size: " << this->max_packet_dump_file_size_mb << std::endl;
    }

    this->packet_timestamp_dynfield_offset = packet_timestamp_dynfield_offset;

    pcap_handler = pcap_open_dead(DLT_EN10MB, 65535);
}

packet_dumper::~packet_dumper()
{
    if (dump_handler) {
        pcap_dump_close(dump_handler);
        dump_handler = nullptr;
    }

    if (pcap_handler) {
        pcap_close(pcap_handler);
        pcap_handler = nullptr;
    }
}

bool packet_dumper::createPacketDumpFile()
{
    const auto now = std::chrono::system_clock::now();
    std::time_t time_now = std::chrono::system_clock::to_time_t(now);
    std::tm local_time = *(std::localtime(&time_now));
    
    std::ostringstream file_name;
    file_name << "dump" << "_" << std::this_thread::get_id() << "_" << std::put_time(&local_time, "%Y%m%d-%H%M%S") 
              << "_" << std::to_string(file_counter++) << ".cap";

    std::filesystem::path file_path = std::filesystem::path(dump_pcap_dir) / std::filesystem::path(file_name.str());
    dump_handler = pcap_dump_open(pcap_handler, file_path.string().c_str());
    return (dump_handler != nullptr);
}

void packet_dumper::flush()
{
    if (dump_handler) {
        pcap_dump_flush(dump_handler);
    }
}

bool packet_dumper::dump(rte_mbuf* packet)
{
    if (!packet->data_len) {
        return false;
    }

    if (!dump_handler) {
        if (!createPacketDumpFile()) {
            std::cerr << "Unable to create packet dump file. " << std::endl;
            return false;
        }
    }

    const uint32_t file_size = pcap_dump_ftell(dump_handler);
    if (unlikely(static_cast<uint32_t>(file_size / (1024 * 1024)) >= max_packet_dump_file_size_mb)) {
        pcap_dump_close(dump_handler);
        dump_handler = nullptr;

        if (!createPacketDumpFile()) {
            std::cerr << "Unable to create packet dump file. " << std::endl;
            return false;
        }
    }

    uint8_t *pkt_data = rte_pktmbuf_mtod(packet, uint8_t *);
    pcap_pkthdr pcap_pkt_header;

    if (packet_timestamp_dynfield_offset >= 0) {
        const uint64_t packet_timestamp = *(RTE_MBUF_DYNFIELD(packet, this->packet_timestamp_dynfield_offset, uint64_t *));
        pcap_pkt_header.ts.tv_sec = packet_timestamp / 1000000000;
        pcap_pkt_header.ts.tv_usec = (packet_timestamp % 1000000000) / 1000;
    }

    pcap_pkt_header.caplen = packet->data_len;
    pcap_pkt_header.len = packet->data_len;

    pcap_dump(reinterpret_cast<uint8_t *>(dump_handler), &pcap_pkt_header, pkt_data);
    return true;
}
