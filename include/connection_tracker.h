#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include "packet_parser.h"
#include "rule_manager.h"
#include <unordered_map>
#include <vector>
#include <map>
#include <string>
#include <mutex>

namespace DPI {

class WfpEnforcement;

class ConnectionTracker {
public:
    ConnectionTracker();
    
    // Tracks flow and Decides FORWARD / DROP
    PacketAction process(const PacketAnalyzer::ParsedPacket& pkt,
                         const std::optional<AppClassification>& classification);

    // Outputs the active connections and statistical histogram
    void generateReport();
    
    // Access rule manager to configure blocks
    RuleManager& getRuleManager() { return rule_manager_; }

    void setEnforcement(WfpEnforcement* enforcement);
    void reinstallWfpRules();

    std::vector<std::string> getDnsQueries() const { std::lock_guard<std::mutex> lock(mutex_); return dns_queries_; }
    std::vector<std::string> getHttpRequests() const { std::lock_guard<std::mutex> lock(mutex_); return http_requests_; }
    std::vector<std::string> getAlerts() const { std::lock_guard<std::mutex> lock(mutex_); return alerts_; }
    std::vector<FlowRecord> getRecentFlows() const { std::lock_guard<std::mutex> lock(mutex_); return recent_flows_; }
    std::map<std::string, size_t> getApplicationStats() const;
    std::map<std::string, size_t> getDomainStats() const;
    size_t getConnectionsCount() const { std::lock_guard<std::mutex> lock(mutex_); return connections_.size(); }
    size_t getDroppedCount() const { std::lock_guard<std::mutex> lock(mutex_); return dropped_count_; }

    // Resolve app name from domain (using critical_websites registry if matched)
    std::string resolveAppName(const std::string& domain) const;
    void loadCriticalWebsites(const std::string& filename = "critical_websites.json");

    struct DnsEntry {
        std::string domain;
        uint32_t    ttl = 300;
        std::chrono::steady_clock::time_point expires_at;
    };

private:
    mutable std::mutex mutex_;
    std::unordered_map<FiveTuple, Connection, FiveTupleHash> connections_;
    std::vector<FlowRecord> recent_flows_;
    std::vector<std::string> dns_queries_;
    std::vector<std::string> http_requests_;
    std::vector<std::string> alerts_;
    // Hostname evidence is separate from flows because browsers commonly reuse
    // one DNS socket for many unrelated website lookups.
    std::map<std::string, size_t> observed_applications_;
    std::map<std::string, size_t> observed_domains_;
    RuleManager rule_manager_;
    WfpEnforcement* enforcement_ = nullptr;
    
    // IP -> domain cache built from DNS responses with TTL expiration
    std::unordered_map<uint32_t, DnsEntry> ip_to_domain_;
    
    // Critical websites registry loaded from JSON: name -> list of wildcard patterns
    std::vector<std::pair<std::string, std::vector<std::string>>> critical_websites_;
    
    size_t total_seen_ = 0;
    size_t dropped_count_ = 0;
    
    Connection* getOrCreateConnection(const FiveTuple& tuple);
    void recordHostnameObservation(const std::string& domain);
    void learnDnsMapping(const std::string& domain, uint32_t ip, uint32_t ttl = 300);
    std::string lookupDomainForIP(uint32_t ip);
};

} // namespace DPI

#endif // CONNECTION_TRACKER_H
