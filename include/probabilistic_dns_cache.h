#ifndef PROBABILISTIC_DNS_CACHE_H
#define PROBABILISTIC_DNS_CACHE_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <shared_mutex>
#include <mutex>
#include <optional>

namespace DPI {

// Record representing an observed domain mapping for an IP
struct DnsRecord {
    std::string domain;
    uint32_t ttl = 300;
    std::chrono::steady_clock::time_point expires_at;
    uint32_t weight = 1; // Observation count / confidence weight
};

// Thread-safe probabilistic multi-domain DNS cache
// Tracks multiple domains mapped to the same IP, ranked by observation weight,
// resolving multi-tenant CDNs and shared virtual hosts.
class ProbabilisticDnsCache {
public:
    static constexpr size_t MAX_DOMAINS_PER_IP = 5;
    static constexpr size_t MAX_CACHE_ENTRIES = 16384;

    ProbabilisticDnsCache() = default;
    ~ProbabilisticDnsCache() = default;

    // Disallow copy to avoid mutex copying
    ProbabilisticDnsCache(const ProbabilisticDnsCache&) = delete;
    ProbabilisticDnsCache& operator=(const ProbabilisticDnsCache&) = delete;

    // Learn or update a domain->IP mapping
    void learnDnsMapping(const std::string& domain, uint32_t ip, uint32_t ttl = 300);

    // Return all valid (non-expired) domains for this IP sorted by weight (highest first)
    std::vector<std::string> getDomainsForIP(uint32_t ip) const;

    // Return the highest-weight non-expired domain for this IP, or empty string
    std::string getBestDomainForIP(uint32_t ip) const;

    // Return full DnsRecord structures for this IP
    std::vector<DnsRecord> getRecordsForIP(uint32_t ip) const;

    // Ambiguity metric: count of times a new domain was mapped to an IP already having entries
    int getOverwriteCount() const;

    // Return active mapping snapshot (e.g. for firewall / WFP synchronization)
    std::unordered_map<uint32_t, std::string> getActiveMappings() const;

    // Evict expired entries; returns number of IP entries removed or pruned
    size_t cleanupExpired();

    // Cache size (number of unique IPs tracked)
    size_t size() const;

    // Clear all entries
    void clear();

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, std::vector<DnsRecord>> cache_;
    int overwrite_count_ = 0;

    void cleanupExpiredUnlocked();
    static std::string normalizeDomain(const std::string& domain);
};

} // namespace DPI

#endif // PROBABILISTIC_DNS_CACHE_H

