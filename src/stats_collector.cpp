#include "stats_collector.h"
#include "wfp_enforcement.h"
#include "packet_queue.h"
#include "types.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif



namespace DPI {

StatsCollector::StatsCollector() {
    start_time_ = std::chrono::steady_clock::now();
    last_print_time_ = start_time_;
    session_id_ = std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

void StatsCollector::update(const PacketAnalyzer::RawPacket& raw, const PacketAnalyzer::ParsedPacket& parsed,
                            const std::optional<AppClassification>& classification, PacketAction action) {
    std::lock_guard<std::mutex> lock(mutex_);

    // If incl_len == 0 (e.g. read timeout dummy packet), skip counter increments
    if (raw.header.incl_len == 0 && raw.data.empty()) return;

    total_packets_++;
    interval_packets_++;
    analytics_.update(raw, parsed, classification, action, total_packets_);
    total_bytes_ += raw.header.orig_len > 0 ? raw.header.orig_len : raw.header.incl_len;
    
    if (parsed.has_ip) {
        if (parsed.protocol == 6 || parsed.has_tcp) { // TCP
            tcp_packets_++;
        } else if (parsed.protocol == 17 || parsed.has_udp) { // UDP
            udp_packets_++;
        } else if (parsed.protocol == 1 || parsed.protocol == 58) { // ICMP
            icmp_packets_++;
        } else {
            other_packets_++;
        }
    } else if (parsed.ether_type == PacketAnalyzer::EtherType::ARP) {
        arp_packets_++;
    } else {
        other_packets_++;
    }
}

void StatsCollector::printMetrics(double pps) {
    double tcp_pct = total_packets_ > 0 ? (100.0 * tcp_packets_ / total_packets_) : 0.0;
    double udp_pct = total_packets_ > 0 ? (100.0 * udp_packets_ / total_packets_) : 0.0;
    double icmp_pct = total_packets_ > 0 ? (100.0 * icmp_packets_ / total_packets_) : 0.0;

    std::cout << "\nPackets: " << total_packets_ << " (PPS: " << std::fixed << std::setprecision(1) << pps << ")\n";
    std::cout << "Bytes: " << total_bytes_ << "\n";
    std::cout << "TCP: " << std::fixed << std::setprecision(1) << tcp_pct << "%\n";
    std::cout << "UDP: " << std::fixed << std::setprecision(1) << udp_pct << "%\n";
    std::cout << "ICMP: " << std::fixed << std::setprecision(1) << icmp_pct << "%\n";
}

static std::string escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 10);
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 32) {
            // ignore unprintable control characters
        } else {
            out += c;
        }
    }
    return out;
}

void StatsCollector::exportJson(const std::string& filename, 
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
                                bool final_snapshot) {
    const std::string temp_filename = filename + ".tmp";
    std::ofstream out(temp_filename, std::ios::trunc);
    if (!out.is_open()) return;

    const auto clock_now = std::chrono::system_clock::now();
    const std::time_t now = std::chrono::system_clock::to_time_t(clock_now);
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(clock_now.time_since_epoch()).count() % 1000;
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    out << "{\n";
    out << "  \"schema_version\": 1,\n";
    out << "  \"generated_at\": \"" << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << "." << std::setw(3) << std::setfill('0') << millis << "Z" << "\",\n";
    out << "  \"engine_state\": \"" << (final_snapshot ? "stopped" : "running") << "\",\n";
    out << "  \"session_id\": \"" << session_id_ << "\",\n";
    out << "  \"parse_errors\": " << parse_errors_ << ",\n";
    out << "  \"analysis\": " << analytics_.toJson() << ",\n";
    out << "  \"packets\": " << total_packets_ << ",\n";
    out << "  \"bytes\": " << total_bytes_ << ",\n";
    out << "  \"connections\": " << connections << ",\n";
    out << "  \"dropped\": " << dropped << ",\n";
    out << "  \"capture_drops\": " << capture_drops << ",\n";
    out << "  \"processing_drops\": " << processing_drops << ",\n";
    if (packet_queue_) {
        out << "  \"queue_size\": " << packet_queue_->size() << ",\n";
        out << "  \"max_queue_depth\": " << packet_queue_->getMaxQueueDepth() << ",\n";
        out << "  \"packets_pushed\": " << packet_queue_->getPacketsPushed() << ",\n";
        out << "  \"packets_popped\": " << packet_queue_->getPacketsPopped() << ",\n";
    }
    out << "  \"mode\": \"" << escapeJson(mode_) << "\",\n";

    out << "  \"source_name\": \"" << escapeJson(source_name_) << "\",\n";
    out << "  \"protection_requested\": " << (protection_requested_ ? "true" : "false") << ",\n";
    out << "  \"protocols\": { \"TCP\": " << tcp_packets_ << ", \"UDP\": " << udp_packets_ << ", \"ICMP\": " << icmp_packets_ << ", \"ARP\": " << arp_packets_ << ", \"Other\": " << other_packets_ << " },\n";
    
    // Applications breakdown (e.g. YouTube, GitHub, LeetCode, Unstop)
    out << "  \"applications\": {";
    size_t app_idx = 0;
    for (const auto& kv : apps) {
        out << "\"" << escapeJson(kv.first) << "\": " << kv.second;
        if (app_idx < apps.size() - 1) out << ", ";
        app_idx++;
    }
    out << "},\n";

    // Domains breakdown (actual FQDNs e.g. unstop.com, api.github.com)
    out << "  \"domains\": {";
    size_t dom_idx = 0;
    for (const auto& kv : domains) {
        out << "\"" << escapeJson(kv.first) << "\": " << kv.second;
        if (dom_idx < domains.size() - 1) out << ", ";
        dom_idx++;
    }
    out << "},\n";
    
    out << "  \"dns\": [";
    for(size_t i = 0; i < dns.size(); ++i) {
        out << "\"" << escapeJson(dns[i]) << "\"";
        if (i < dns.size() - 1) out << ", ";
    }
    out << "],\n";
    
    out << "  \"http\": [";
    for(size_t i = 0; i < http.size(); ++i) {
        out << "\"" << escapeJson(http[i]) << "\"";
        if (i < http.size() - 1) out << ", ";
    }
    out << "],\n";
    
    out << "  \"alerts\": [";
    for(size_t i = 0; i < alerts.size(); ++i) {
        out << "\"" << escapeJson(alerts[i]) << "\"";
        if (i < alerts.size() - 1) out << ", ";
    }
    out << "],\n";

    // Recent flows table (50-100 flows)
    out << "  \"flows\": [\n";
    for (size_t i = 0; i < flows.size(); ++i) {
        const auto& f = flows[i];
        out << "    { "
            << "\"packets\": " << f.packets << ", "
            << "\"bytes\": " << f.bytes << ", "
            << "\"first_seen_us\": " << f.first_seen_us << ", "
            << "\"last_seen_us\": " << f.last_seen_us << ", "
            << "\"time\": \"" << escapeJson(f.timestamp) << "\", "
            << "\"src_ip\": \"" << escapeJson(f.src_ip) << "\", "
            << "\"src_port\": " << f.src_port << ", "
            << "\"dst_ip\": \"" << escapeJson(f.dst_ip) << "\", "
            << "\"dst_port\": " << f.dst_port << ", "
            << "\"protocol\": \"" << escapeJson(f.protocol) << "\", "
            << "\"domain\": \"" << escapeJson(f.domain) << "\", "
            << "\"application\": \"" << escapeJson(f.application) << "\", "
            << "\"method\": \"" << escapeJson(f.method) << "\", "
            << "\"confidence\": \"" << escapeJson(f.confidence) << "\", "
            << "\"policy_reason\": \"" << escapeJson(f.policy_reason) << "\", "
            << "\"policy\": \"" << escapeJson(f.policy) << "\", "
            << "\"enforcement\": \"" << escapeJson(f.enforcement) << "\""
            << " }";
        if (i < flows.size() - 1) out << ",";
        out << "\n";
    }
    out << "  ],\n";
    
    if (wfp_enforcement_) {
        out << "  " << wfp_enforcement_->getStateJson() << "\n";
    } else {
        out << "  \"wfp\": { \"active\": false, \"status\": \"OFF (Monitor Mode)\", \"ip_filters\": 0, \"port_filters\": 0, \"domain_rules\": 0, \"total_filters\": 0 }\n";
    }
    out << "}\n";
    out.close();
    if (!out) {
        std::remove(temp_filename.c_str());
        return;
    }
#ifdef _WIN32
    if (!MoveFileExA(temp_filename.c_str(), filename.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::cerr << "[Telemetry] Could not replace " << filename << "\n";
        std::remove(temp_filename.c_str());
    }
#else
    if (std::rename(temp_filename.c_str(), filename.c_str()) != 0) {
        std::cerr << "[Telemetry] Could not replace " << filename << "\n";
        std::remove(temp_filename.c_str());
    }
#endif
}

void StatsCollector::checkAndPrint(const std::vector<std::string>& dns, 
                                  const std::vector<std::string>& http, 
                                  const std::vector<std::string>& tracker_alerts, 
                                  const std::map<std::string, size_t>& apps, 
                                  const std::map<std::string, size_t>& domains,
                                  const std::vector<FlowRecord>& flows,
                                  size_t connections, 
                                  size_t dropped,
                                  uint64_t capture_drops,
                                  uint64_t processing_drops,
                                  uint64_t interval_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_print_time_).count();
    
    if (elapsed >= static_cast<int64_t>(interval_ms)) {
        double pps = (interval_packets_ * 1000.0) / (elapsed > 0 ? elapsed : 1);
        
        if (mode_ == "live" && pps > 2000.0) {
            std::string msg = "High processing rate (>2000 packets/s)";
            if (local_alerts_.size() < 10) {
                local_alerts_.push_back(msg);
            }
        }
        
        std::vector<std::string> combined_alerts = tracker_alerts;
        combined_alerts.insert(combined_alerts.end(), local_alerts_.begin(), local_alerts_.end());
        
        exportJson("output.json", dns, http, combined_alerts, apps, domains, flows, connections, dropped, capture_drops, processing_drops, false);
        
        last_print_time_ = now;
        interval_packets_ = 0;
    }
}

void StatsCollector::printFinal(const std::vector<std::string>& dns, 
                                const std::vector<std::string>& http, 
                                const std::vector<std::string>& tracker_alerts, 
                                const std::map<std::string, size_t>& apps, 
                                const std::map<std::string, size_t>& domains,
                                const std::vector<FlowRecord>& flows,
                                size_t connections, 
                                size_t dropped,
                                uint64_t capture_drops,
                                uint64_t processing_drops) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto elapsed_total = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
    
    double avg_pps = 0.0;
    if (elapsed_total > 0) {
        avg_pps = (total_packets_ * 1000.0) / elapsed_total;
    }
    
    std::vector<std::string> combined_alerts = tracker_alerts;
    combined_alerts.insert(combined_alerts.end(), local_alerts_.begin(), local_alerts_.end());
    
    exportJson("output.json", dns, http, combined_alerts, apps, domains, flows, connections, dropped, capture_drops, processing_drops, true);
    printMetrics(avg_pps);
}

} // namespace DPI
