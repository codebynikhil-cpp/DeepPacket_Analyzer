#include "traffic_analytics.h"
#include "vendor/nlohmann/json.hpp"
#include <algorithm>

namespace DPI {
namespace {
constexpr size_t packetLimit = 300, aggregateLimit = 4096, timelineLimit = 300;
std::string protocolName(const PacketAnalyzer::ParsedPacket& p) {
    if (p.ether_type == PacketAnalyzer::EtherType::ARP) return "ARP";
    if (!p.has_ip) return "Other";
    return PacketAnalyzer::PacketParser::protocolToString(p.protocol);
}
}

void TrafficAnalytics::update(const PacketAnalyzer::RawPacket& raw, const PacketAnalyzer::ParsedPacket& p,
                             const std::optional<AppClassification>& classification, PacketAction action, uint64_t id) {
    const uint64_t time = static_cast<uint64_t>(raw.header.ts_sec) * 1000000 + raw.header.ts_usec;
    const uint32_t length = raw.header.orig_len ? raw.header.orig_len : raw.header.incl_len;
    if (!has_packet_) { first_us_ = last_us_ = time; has_packet_ = true; }
    first_us_ = std::min(first_us_, time);
    last_us_ = std::max(last_us_, time);
    auto& bucket = timeline_[time / 1000000];
    ++bucket.packets; bucket.bytes += length;
    while (timeline_.size() > timelineLimit || (!timeline_.empty() && timeline_.begin()->first + timelineLimit <= last_us_ / 1000000))
        timeline_.erase(timeline_.begin());
    const size_t sizeIndex = length <= 64 ? 0 : length <= 128 ? 1 : length <= 256 ? 2 : length <= 512 ? 3 : length <= 1024 ? 4 : 5;
    ++sizes_[sizeIndex];
    if (p.has_ip) {
        auto endpoint = [&](const std::string& ip, bool source) {
            auto it = endpoints_.find(ip);
            if (it == endpoints_.end()) {
                if (endpoints_.size() >= aggregateLimit) { endpoints_limited_ = true; return; }
                it = endpoints_.emplace(ip, Endpoint{}).first;
            }
            if (source) { ++it->second.sent_packets; it->second.sent_bytes += length; }
            else { ++it->second.received_packets; it->second.received_bytes += length; }
        };
        endpoint(p.src_ip, true); endpoint(p.dest_ip, false);
    }
    if (p.has_tcp || p.has_udp) {
        auto port = [&](uint16_t value, bool source) {
            const uint32_t key = (static_cast<uint32_t>(p.protocol) << 16) | value;
            auto it = ports_.find(key);
            if (it == ports_.end()) {
                if (ports_.size() >= aggregateLimit) { ports_limited_ = true; return; }
                it = ports_.emplace(key, Port{}).first;
            }
            if (source) ++it->second.source_packets; else ++it->second.destination_packets;
            it->second.bytes += length;
        };
        port(p.src_port, true); port(p.dest_port, false);
    }
    PacketRecord record;
    record.id = id; record.timestamp_us = time; record.length = length; record.captured_length = raw.header.incl_len;
    record.headers = p;
    record.headers.payload_data = nullptr;
    record.action = action;
    if (classification) {
        record.application = appTypeToString(classification->app);
        record.method = classification->method;
        record.domain = classification->sni_or_host;
        if (!classification->http_method.empty()) record.info = classification->http_method + " " + classification->http_path.substr(0, 256);
    }
    if (record.info.empty()) {
        if (p.is_noninitial_fragment) record.info = "IP fragment (transport header unavailable)";
        else if (p.has_tcp) record.info = PacketAnalyzer::PacketParser::tcpFlagsToString(p.tcp_flags);
        else if (p.has_udp && !record.domain.empty()) record.info = "DNS name: " + record.domain;
        else record.info = protocolName(p) + " frame";
    }
    packets_.push_back(std::move(record));
    if (packets_.size() > packetLimit) packets_.pop_front();
}

std::string TrafficAnalytics::toJson() const {
    using nlohmann::json;
    json out = {{"packet_limit", packetLimit}, {"timeline_seconds", timelineLimit}, {"aggregate_limit", aggregateLimit},
                {"tracked_endpoints", endpoints_.size()}, {"endpoints_limited", endpoints_limited_}, {"ports_limited", ports_limited_}};
    out["capture_start_us"] = has_packet_ ? json(first_us_) : json(nullptr);
    out["capture_end_us"] = has_packet_ ? json(last_us_) : json(nullptr);
    out["capture_duration_ms"] = has_packet_ ? json((last_us_ - first_us_) / 1000.0) : json(nullptr);
    out["recent_packets"] = json::array();
    for (const auto& record : packets_) {
        const auto& p = record.headers;
        out["recent_packets"].push_back({
            {"id", record.id}, {"timestamp_us", record.timestamp_us}, {"length", record.length}, {"captured_length", record.captured_length},
            {"src_mac", p.src_mac}, {"dst_mac", p.dest_mac}, {"ether_type", p.ether_type},
            {"src_ip", p.has_ip ? json(p.src_ip) : json(nullptr)}, {"dst_ip", p.has_ip ? json(p.dest_ip) : json(nullptr)},
            {"ip_version", p.has_ip ? json(p.ip_version) : json(nullptr)}, {"ttl", p.has_ip ? json(p.ttl) : json(nullptr)},
            {"protocol", protocolName(p)}, {"protocol_number", p.has_ip ? json(p.protocol) : json(nullptr)},
            {"src_port", p.has_tcp || p.has_udp ? json(p.src_port) : json(nullptr)},
            {"dst_port", p.has_tcp || p.has_udp ? json(p.dest_port) : json(nullptr)},
            {"tcp_flags", p.has_tcp ? json(PacketAnalyzer::PacketParser::tcpFlagsToString(p.tcp_flags)) : json(nullptr)},
            {"sequence", p.has_tcp ? json(p.seq_number) : json(nullptr)}, {"acknowledgment", p.has_tcp ? json(p.ack_number) : json(nullptr)},
            {"payload_length", p.payload_length}, {"fragment", p.is_noninitial_fragment},
            {"application", record.application}, {"domain", record.domain}, {"info", record.info}, {"method", record.method},
            {"policy", record.action == PacketAction::DROP ? "DROP" : "FORWARD"}
        });
    }
    out["timeline"] = json::array();
    for (const auto& [second, bucket] : timeline_)
        out["timeline"].push_back({{"time_ms", second * 1000}, {"packets", bucket.packets}, {"bytes", bucket.bytes}});
    const char* labels[] = {"0–64", "65–128", "129–256", "257–512", "513–1024", "1025+"};
    out["size_distribution"] = json::array();
    for (size_t i = 0; i < sizes_.size(); ++i) out["size_distribution"].push_back({{"label", labels[i]}, {"packets", sizes_[i]}});
    std::vector<std::pair<std::string, Endpoint>> ranked(endpoints_.begin(), endpoints_.end());
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
        const auto av = a.second.sent_bytes + a.second.received_bytes, bv = b.second.sent_bytes + b.second.received_bytes;
        return av == bv ? a.first < b.first : av > bv;
    });
    out["top_talkers"] = json::array();
    for (size_t i = 0; i < std::min<size_t>(20, ranked.size()); ++i) {
        const auto& [ip, e] = ranked[i];
        out["top_talkers"].push_back({{"ip", ip}, {"sent_packets", e.sent_packets}, {"received_packets", e.received_packets},
                                    {"sent_bytes", e.sent_bytes}, {"received_bytes", e.received_bytes}});
    }
    std::vector<std::pair<uint32_t, Port>> rankedPorts(ports_.begin(), ports_.end());
    std::sort(rankedPorts.begin(), rankedPorts.end(), [](const auto& a, const auto& b) {
        const auto av = a.second.source_packets + a.second.destination_packets, bv = b.second.source_packets + b.second.destination_packets;
        return av == bv ? a.first < b.first : av > bv;
    });
    out["ports"] = json::array();
    for (size_t i = 0; i < std::min<size_t>(20, rankedPorts.size()); ++i) {
        const auto& [key, port] = rankedPorts[i];
        out["ports"].push_back({{"port", key & 0xffff}, {"protocol", key >> 16 == 6 ? "TCP" : "UDP"},
                               {"source_packets", port.source_packets}, {"destination_packets", port.destination_packets}, {"bytes", port.bytes}});
    }
    return out.dump(-1, ' ', false, json::error_handler_t::replace);
}
}
