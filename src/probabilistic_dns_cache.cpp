#include "probabilistic_dns_cache.h"
#include <algorithm>
#include <cctype>

namespace DPI {

std::string ProbabilisticDnsCache::normalizeDomain(const std::string& domain) {
    if (domain.empty()) return "";
    std::string norm = domain;
    std::transform(norm.begin(), norm.end(), norm.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!norm.empty() && (norm.back() == '.' || norm.back() == ' ')) {
        norm.pop_back();
    }
    return norm;
}

void ProbabilisticDnsCache::cleanupExpiredUnlocked() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = cache_.begin(); it != cache_.end();) {
        auto& records = it->second;
        records.erase(
            std::remove_if(records.begin(), records.end(),
                           [&now](const DnsRecord& r) { return r.expires_at <= now; }),
            records.end());
        if (records.empty()) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

void ProbabilisticDnsCache::learnDnsMapping(const std::string& domain, uint32_t ip, uint32_t ttl) {
    if (ip == 0 || domain.empty()) return;
    if (ttl == 0) ttl = 300; // Default 5 minutes

    const std::string norm = normalizeDomain(domain);
    if (norm.empty()) return;

    const auto now = std::chrono::steady_clock::now();
    const auto expires = now + std::chrono::seconds(ttl);

    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = cache_.find(ip);
    if (it != cache_.end()) {
        auto& records = it->second;
        bool found = false;

        for (auto& rec : records) {
            if (rec.domain == norm) {
                rec.ttl = ttl;
                rec.expires_at = expires;
                rec.weight += 1;
                found = true;
                break;
            }
        }

        if (!found) {
            // New domain added to existing IP -> ambiguity detected!
            overwrite_count_++;
            records.push_back(DnsRecord{norm, ttl, expires, 1});
        }

        // Sort descending by weight; if equal, later expiration first
        std::stable_sort(records.begin(), records.end(),
                         [](const DnsRecord& a, const DnsRecord& b) {
                             if (a.weight != b.weight) return a.weight > b.weight;
                             return a.expires_at > b.expires_at;
                         });

        // Cap to MAX_DOMAINS_PER_IP (5)
        if (records.size() > MAX_DOMAINS_PER_IP) {
            records.resize(MAX_DOMAINS_PER_IP);
        }
    } else {
        // Enforce maximum cache table size
        if (cache_.size() >= MAX_CACHE_ENTRIES) {
            cleanupExpiredUnlocked();
            if (cache_.size() >= MAX_CACHE_ENTRIES) {
                cache_.erase(cache_.begin());
            }
        }

        std::vector<DnsRecord> vec;
        vec.reserve(MAX_DOMAINS_PER_IP);
        vec.push_back(DnsRecord{norm, ttl, expires, 1});
        cache_.emplace(ip, std::move(vec));
    }
}

std::vector<std::string> ProbabilisticDnsCache::getDomainsForIP(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = cache_.find(ip);
    if (it == cache_.end()) return {};

    const auto now = std::chrono::steady_clock::now();
    std::vector<std::string> domains;
    domains.reserve(it->second.size());

    for (const auto& rec : it->second) {
        if (rec.expires_at > now) {
            domains.push_back(rec.domain);
        }
    }
    return domains;
}

std::string ProbabilisticDnsCache::getBestDomainForIP(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = cache_.find(ip);
    if (it == cache_.end()) return "";

    const auto now = std::chrono::steady_clock::now();
    for (const auto& rec : it->second) {
        if (rec.expires_at > now) {
            return rec.domain; // Already sorted by weight descending
        }
    }
    return "";
}

std::vector<DnsRecord> ProbabilisticDnsCache::getRecordsForIP(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = cache_.find(ip);
    if (it == cache_.end()) return {};

    const auto now = std::chrono::steady_clock::now();
    std::vector<DnsRecord> records;
    records.reserve(it->second.size());

    for (const auto& rec : it->second) {
        if (rec.expires_at > now) {
            records.push_back(rec);
        }
    }
    return records;
}

int ProbabilisticDnsCache::getOverwriteCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return overwrite_count_;
}

std::unordered_map<uint32_t, std::string> ProbabilisticDnsCache::getActiveMappings() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::unordered_map<uint32_t, std::string> result;
    const auto now = std::chrono::steady_clock::now();

    for (const auto& kv : cache_) {
        for (const auto& rec : kv.second) {
            if (rec.expires_at > now) {
                result[kv.first] = rec.domain;
                break;
            }
        }
    }
    return result;
}

size_t ProbabilisticDnsCache::cleanupExpired() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    size_t initial_count = cache_.size();
    cleanupExpiredUnlocked();
    return initial_count - cache_.size();
}

size_t ProbabilisticDnsCache::size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return cache_.size();
}

void ProbabilisticDnsCache::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    cache_.clear();
    overwrite_count_ = 0;
}

} // namespace DPI

