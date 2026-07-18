// MIT License
//
// Copyright (c) 2026 Muhammad Awais Khalid

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>

#include <ndpi_util.hpp>

constexpr uint32_t DEFAULT_MAX_FLOWS = 65536;
constexpr uint32_t DEFAULT_IDLE_TIMEOUT_SEC = 60;

struct FlowKey {
    uint8_t l3_version {4}; // 4 or 6
    uint8_t l4_proto {0};
    uint8_t ip_a[16] {};
    uint8_t ip_b[16] {};
    uint16_t port_a {0};
    uint16_t port_b {0};

    bool operator==(const FlowKey &other) const
    {
        return l3_version == other.l3_version
            && l4_proto == other.l4_proto
            && port_a == other.port_a
            && port_b == other.port_b
            && std::memcmp(ip_a, other.ip_a, sizeof(ip_a)) == 0
            && std::memcmp(ip_b, other.ip_b, sizeof(ip_b)) == 0;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey &key) const noexcept
    {
        size_t h = (static_cast<size_t>(key.l3_version) << 8) | key.l4_proto;
        h ^= (static_cast<size_t>(key.port_a) << 16) ^ key.port_b;
        for (uint8_t b : key.ip_a) {
            h = h * 131 + b;
        }
        for (uint8_t b : key.ip_b) {
            h = h * 131 + b;
        }
        return h;
    }
};

inline int compare_endpoint(const uint8_t *ip_a, uint16_t port_a,
                            const uint8_t *ip_b, uint16_t port_b)
{
    const int cmp = std::memcmp(ip_a, ip_b, 16);
    if (cmp < 0) {
        return -1;
    }
    if (cmp > 0) {
        return 1;
    }
    if (port_a < port_b) {
        return -1;
    }
    if (port_a > port_b) {
        return 1;
    }
    return 0;
}

// Normalize so both directions of a connection hash to the same key.
inline FlowKey make_flow_key(uint8_t l3_version, uint8_t l4_proto,
                             const uint8_t *src_ip, uint16_t src_port,
                             const uint8_t *dst_ip, uint16_t dst_port)
{
    FlowKey key {};
    key.l3_version = l3_version;
    key.l4_proto = l4_proto;

    uint8_t src[16] {};
    uint8_t dst[16] {};
    const size_t ip_len = (l3_version == 6) ? 16 : 4;
    std::memcpy(src, src_ip, ip_len);
    std::memcpy(dst, dst_ip, ip_len);

    if (compare_endpoint(src, src_port, dst, dst_port) <= 0) {
        std::memcpy(key.ip_a, src, sizeof(src));
        std::memcpy(key.ip_b, dst, sizeof(dst));
        key.port_a = src_port;
        key.port_b = dst_port;
    } else {
        std::memcpy(key.ip_a, dst, sizeof(dst));
        std::memcpy(key.ip_b, src, sizeof(src));
        key.port_a = dst_port;
        key.port_b = src_port;
    }
    return key;
}

struct FlowEntry {
    ndpi_flow_struct *ndpi_flow {nullptr};
    ndpi_protocol detected {};
    bool detection_completed {false};
    uint64_t packets {0};
    uint64_t bytes {0};
    uint64_t last_seen_ms {0};
};

class FlowTable {
public:
    explicit FlowTable(uint32_t max_flows = DEFAULT_MAX_FLOWS,
                       uint32_t idle_timeout_sec = DEFAULT_IDLE_TIMEOUT_SEC)
        : max_flows_(max_flows)
        , idle_timeout_ms_(static_cast<uint64_t>(idle_timeout_sec) * 1000ULL)
    {
    }

    ~FlowTable()
    {
        clear();
    }

    FlowTable(const FlowTable &) = delete;
    FlowTable &operator=(const FlowTable &) = delete;

    FlowEntry *get_or_create(const FlowKey &key, uint64_t now_ms, bool &created, bool &rejected)
    {
        created = false;
        rejected = false;

        auto it = table_.find(key);
        if (it != table_.end()) {
            it->second.last_seen_ms = now_ms;
            return &it->second;
        }

        if (table_.size() >= max_flows_) {
            rejected = true;
            return nullptr;
        }

        FlowEntry entry {};
        entry.ndpi_flow = ndpi_util::alloc_flow();
        if (!entry.ndpi_flow) {
            rejected = true;
            return nullptr;
        }
        entry.detected = NDPI_PROTOCOL_NULL;
        entry.last_seen_ms = now_ms;

        auto [inserted, ok] = table_.emplace(key, entry);
        if (!ok) {
            ndpi_util::free_flow(entry.ndpi_flow);
            rejected = true;
            return nullptr;
        }

        created = true;
        return &inserted->second;
    }

    uint32_t expire_idle(uint64_t now_ms)
    {
        uint32_t removed = 0;
        for (auto it = table_.begin(); it != table_.end(); ) {
            if (now_ms - it->second.last_seen_ms >= idle_timeout_ms_) {
                ndpi_util::free_flow(it->second.ndpi_flow);
                it = table_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    }

    size_t size() const
    {
        return table_.size();
    }

    void clear()
    {
        for (auto &kv : table_) {
            ndpi_util::free_flow(kv.second.ndpi_flow);
            kv.second.ndpi_flow = nullptr;
        }
        table_.clear();
    }

private:
    uint32_t max_flows_;
    uint64_t idle_timeout_ms_;
    std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> table_;
};
