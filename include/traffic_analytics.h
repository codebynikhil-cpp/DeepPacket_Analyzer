#ifndef TRAFFIC_ANALYTICS_H
#define TRAFFIC_ANALYTICS_H

#include "packet_parser.h"
#include "types.h"
#include <array>
#include <deque>
#include <map>
#include <unordered_map>

namespace DPI {

// Access is protected by StatsCollector's mutex. Metadata only: packet payload
// pointers are never retained after the capture buffer is released.
class TrafficAnalytics {
public:
    void update(const PacketAnalyzer::RawPacket& raw, const PacketAnalyzer::ParsedPacket& parsed,
                const std::optional<AppClassification>& classification, PacketAction action, uint64_t id);
    std::string toJson() const;
private:
    struct PacketRecord {
        uint64_t id = 0, timestamp_us = 0;
        uint32_t length = 0, captured_length = 0;
        PacketAnalyzer::ParsedPacket headers{};
        std::string application, domain, info, method;
        PacketAction action = PacketAction::FORWARD;
    };
    struct Endpoint { uint64_t sent_packets = 0, received_packets = 0, sent_bytes = 0, received_bytes = 0; };
    struct Port { uint64_t source_packets = 0, destination_packets = 0, bytes = 0; };
    struct Bucket { uint64_t packets = 0, bytes = 0; };
    std::deque<PacketRecord> packets_;
    std::unordered_map<std::string, Endpoint> endpoints_;
    std::map<uint32_t, Port> ports_;
    std::map<uint64_t, Bucket> timeline_;
    std::array<uint64_t, 6> sizes_{};
    uint64_t first_us_ = 0, last_us_ = 0;
    bool has_packet_ = false, endpoints_limited_ = false, ports_limited_ = false;
};
}
#endif
