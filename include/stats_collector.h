#ifndef STATS_COLLECTOR_H
#define STATS_COLLECTOR_H

#include "pcap_reader.h"
#include "packet_parser.h"
#include "types.h"
#include "traffic_analytics.h"
#include <chrono>
#include <cstdint>
#include <map>
#include <vector>
#include <string>
#include <mutex>

namespace PacketAnalyzer { class PacketQueue; }

namespace DPI {

class WfpEnforcement;

class StatsCollector {
public:
    StatsCollector();

    void setMode(const std::string& mode, const std::string& source_name) {
        std::lock_guard<std::mutex> lock(mutex_);
        mode_ = mode;
        source_name_ = source_name;
    }

    void setWfpEnforcement(const WfpEnforcement* wfp) {
        std::lock_guard<std::mutex> lock(mutex_);
        wfp_enforcement_ = wfp;
    }

    void setPacketQueue(const PacketAnalyzer::PacketQueue* queue) {
        std::lock_guard<std::mutex> lock(mutex_);
        packet_queue_ = queue;
    }


    void setProtectionRequested(bool requested) {
        std::lock_guard<std::mutex> lock(mutex_);
        protection_requested_ = requested;
    }

    void update(const PacketAnalyzer::RawPacket& raw, const PacketAnalyzer::ParsedPacket& parsed,
                const std::optional<AppClassification>& classification, PacketAction action);
    void recordParseError() { std::lock_guard<std::mutex> lock(mutex_); ++parse_errors_; }
    
    void checkAndPrint(const std::vector<std::string>& dns, 
                      const std::vector<std::string>& http, 
                      const std::vector<std::string>& tracker_alerts, 
                      const std::map<std::string, size_t>& apps, 
                      const std::map<std::string, size_t>& domains,
                      const std::vector<FlowRecord>& flows,
                      size_t connections = 0, 
                      size_t dropped = 0,
                      uint64_t capture_drops = 0,
                      uint64_t processing_drops = 0,
                      uint64_t interval_ms = 500);

    void printFinal(const std::vector<std::string>& dns, 
                    const std::vector<std::string>& http, 
                    const std::vector<std::string>& tracker_alerts, 
                    const std::map<std::string, size_t>& apps, 
                    const std::map<std::string, size_t>& domains,
                    const std::vector<FlowRecord>& flows,
                    size_t connections = 0, 
                    size_t dropped = 0,
                    uint64_t capture_drops = 0,
                    uint64_t processing_drops = 0);

private:
    mutable std::mutex mutex_;

    std::string mode_ = "offline";
    std::string source_name_ = "pcap";
    const WfpEnforcement* wfp_enforcement_ = nullptr;
    const PacketAnalyzer::PacketQueue* packet_queue_ = nullptr;
    bool protection_requested_ = false;


    uint64_t total_packets_ = 0;
    uint64_t total_bytes_ = 0;
    uint64_t parse_errors_ = 0;
    TrafficAnalytics analytics_;
    std::string session_id_;
    
    uint64_t tcp_packets_ = 0;
    uint64_t udp_packets_ = 0;
    uint64_t icmp_packets_ = 0;
    uint64_t arp_packets_ = 0;
    uint64_t other_packets_ = 0;
    
    uint64_t interval_packets_ = 0;
    
    std::chrono::steady_clock::time_point last_print_time_;
    std::chrono::steady_clock::time_point start_time_;
    
    std::vector<std::string> local_alerts_;
    
    void printMetrics(double pps);
    void exportJson(const std::string& filename, 
                    const std::vector<std::string>& dns, 
                    const std::vector<std::string>& http, 
                    const std::vector<std::string>& alerts, 
                    const std::map<std::string, size_t>& apps, 
                    const std::map<std::string, size_t>& domains,
                    const std::vector<FlowRecord>& flows,
                    size_t connections, 
                    size_t dropped,
                    uint64_t capture_drops,
                    uint64_t processing_drops,
                    bool final_snapshot);
};

} // namespace DPI

#endif // STATS_COLLECTOR_H
