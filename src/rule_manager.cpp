#include "rule_manager.h"
#include "wfp_enforcement.h"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>
#include "vendor/nlohmann/json.hpp"


namespace DPI {

// ============================================================================
// IP Blocking
// ============================================================================

uint32_t RuleManager::parseIP(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    
    for (char c : ip) {
        if (c == '.') {
            result |= (octet << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (octet << shift);
    
    return result;
}

std::string RuleManager::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

void RuleManager::blockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.insert(ip);
    std::cout << "[RuleManager] Blocked IP: " << ipToString(ip) << std::endl;
    if (enforcement_) {
        enforcement_->blockIP(ip);
    }
}

void RuleManager::blockIP(const std::string& ip) {
    blockIP(parseIP(ip));
}

void RuleManager::unblockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.erase(ip);
    std::cout << "[RuleManager] Unblocked IP: " << ipToString(ip) << std::endl;
    if (enforcement_) {
        enforcement_->unblockIP(ip);
    }
}

void RuleManager::unblockIP(const std::string& ip) {
    unblockIP(parseIP(ip));
}

bool RuleManager::isIPBlocked(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    return blocked_ips_.count(ip) > 0;
}

std::vector<std::string> RuleManager::getBlockedIPs() const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    std::vector<std::string> result;
    for (uint32_t ip : blocked_ips_) {
        result.push_back(ipToString(ip));
    }
    return result;
}

// ============================================================================
// Application Blocking
// ============================================================================

void RuleManager::blockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.insert(app);
    std::cout << "[RuleManager] Blocked app: " << appTypeToString(app) << std::endl;
}

void RuleManager::unblockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.erase(app);
    std::cout << "[RuleManager] Unblocked app: " << appTypeToString(app) << std::endl;
}

bool RuleManager::isAppBlocked(AppType app) const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return blocked_apps_.count(app) > 0;
}

std::vector<AppType> RuleManager::getBlockedApps() const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return std::vector<AppType>(blocked_apps_.begin(), blocked_apps_.end());
}

// ============================================================================
// Domain Blocking
// ============================================================================

void RuleManager::blockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        if (std::find(domain_patterns_.begin(), domain_patterns_.end(), domain) == domain_patterns_.end())
            domain_patterns_.push_back(domain);
    } else {
        blocked_domains_.insert(domain);
    }
    
    std::cout << "[RuleManager] Blocked domain: " << domain << std::endl;
    if (enforcement_) {
        enforcement_->blockDomain(domain, {});
    }
}

void RuleManager::unblockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        auto it = std::find(domain_patterns_.begin(), domain_patterns_.end(), domain);
        if (it != domain_patterns_.end()) {
            domain_patterns_.erase(it);
        }
    } else {
        blocked_domains_.erase(domain);
    }
    
    std::cout << "[RuleManager] Unblocked domain: " << domain << std::endl;
    if (enforcement_) {
        enforcement_->unblockDomain(domain);
    }
}


bool RuleManager::domainMatchesPattern(const std::string& domain, const std::string& pattern) {
    // Handle *.example.com pattern
    if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        std::string suffix = pattern.substr(1);  // .example.com
        
        // Check if domain ends with the pattern
        if (domain.size() >= suffix.size() &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        
        // Also match the bare domain (example.com matches *.example.com)
        if (domain == pattern.substr(2)) {
            return true;
        }
    }
    
    return false;
}

bool RuleManager::isDomainBlocked(const std::string& domain) const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (!lower_domain.empty() && lower_domain.back() == '.') lower_domain.pop_back();
    if (blocked_domains_.count(lower_domain) > 0) return true;
    
    for (const auto& pattern : domain_patterns_) {
        std::string lower_pattern = pattern;
        std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        
        if (domainMatchesPattern(lower_domain, lower_pattern)) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> RuleManager::getBlockedDomains() const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    std::vector<std::string> result(blocked_domains_.begin(), blocked_domains_.end());
    result.insert(result.end(), domain_patterns_.begin(), domain_patterns_.end());
    return result;
}

// ============================================================================
// Port Blocking
// ============================================================================

void RuleManager::blockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.insert(port);
    std::cout << "[RuleManager] Blocked port: " << port << std::endl;
    if (enforcement_) {
        enforcement_->blockPort(port);
    }
}

void RuleManager::unblockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.erase(port);
    if (enforcement_) {
        enforcement_->unblockPort(port);
    }
}

bool RuleManager::isPortBlocked(uint16_t port) const {
    std::shared_lock<std::shared_mutex> lock(port_mutex_);
    return blocked_ports_.count(port) > 0;
}

// ============================================================================
// Combined Check
// ============================================================================

std::optional<RuleManager::BlockReason> RuleManager::shouldBlock(
    uint32_t src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain) const {
    
    // Check IP first (most specific)
    if (isIPBlocked(src_ip)) {
        return BlockReason{BlockReason::IP, ipToString(src_ip)};
    }
    
    // Check port
    if (isPortBlocked(dst_port)) {
        return BlockReason{BlockReason::PORT, std::to_string(dst_port)};
    }
    
    // Check app
    if (isAppBlocked(app)) {
        return BlockReason{BlockReason::APP, appTypeToString(app)};
    }
    
    // Check domain
    if (!domain.empty() && isDomainBlocked(domain)) {
        return BlockReason{BlockReason::DOMAIN_RULE, domain};
    }
    
    return std::nullopt;
}

// ============================================================================
// Persistence
// ============================================================================

bool RuleManager::saveRules(const std::string& filename) const {
    nlohmann::json rules;
    rules["blocked_ips"] = getBlockedIPs();
    rules["blocked_domains"] = getBlockedDomains();
    rules["blocked_apps"] = nlohmann::json::array();
    for (auto app : getBlockedApps()) rules["blocked_apps"].push_back(appTypeToString(app));
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        rules["blocked_ports"] = blocked_ports_;
    }
    std::ofstream file(filename);
    if (!file) return false;
    file << rules.dump(2) << "\n";
    return static_cast<bool>(file);
}

bool RuleManager::loadRules(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return false;
    if (file.tellg() > 1024 * 1024) {
        std::cerr << "[RuleManager] Rules file exceeds 1 MiB. Existing rules retained.\n";
        return false;
    }
    file.seekg(0);
    try {
        const auto rules = nlohmann::json::parse(file);
        if (!rules.is_object()) throw std::runtime_error("Expected a JSON object");
        std::unordered_set<uint32_t> ips;
        std::unordered_set<AppType> apps;
        std::unordered_set<std::string> domains;
        std::vector<std::string> patterns;
        std::unordered_set<uint16_t> ports;
        for (const auto* key : {"blocked_ips", "blocked_apps", "blocked_domains", "blocked_ports"}) {
            if (!rules.contains(key) || !rules[key].is_array())
                throw std::runtime_error(std::string("Expected array: ") + key);
        }
        for (const auto& entry : rules["blocked_ips"]) {
            const std::string value = entry.get<std::string>();
            std::istringstream parts(value);
            std::string octet;
            int count = 0;
            while (std::getline(parts, octet, '.')) {
                if (octet.empty() || octet.size() > 3 ||
                    !std::all_of(octet.begin(), octet.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }) ||
                    std::stoi(octet) > 255) throw std::runtime_error("Invalid IPv4 rule");
                ++count;
            }
            if (count != 4 || value.back() == '.') throw std::runtime_error("Invalid IPv4 rule");
            ips.insert(parseIP(value));
        }
        for (const auto& entry : rules["blocked_apps"]) {
            const auto value = entry.get<std::string>();
            bool found = false;
            for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); ++i) {
                const auto app = static_cast<AppType>(i);
                if (appTypeToString(app) == value) { apps.insert(app); found = true; break; }
            }
            if (!found) throw std::runtime_error("Unknown application rule");
        }
        for (const auto& entry : rules["blocked_domains"]) {
            auto value = entry.get<std::string>();
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::tolower(c); });
            const auto bare = value.rfind("*.", 0) == 0 ? value.substr(2) : value;
            if (bare.empty() || bare.size() > 253 || bare.find('.') == std::string::npos || bare.back() == '.')
                throw std::runtime_error("Invalid domain rule");
            std::istringstream labels(bare);
            std::string label;
            while (std::getline(labels, label, '.')) {
                if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-' ||
                    !std::all_of(label.begin(), label.end(), [](unsigned char c) {
                        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                    })) throw std::runtime_error("Invalid domain rule");
            }
            if (value.rfind("*.", 0) == 0) {
                if (std::find(patterns.begin(), patterns.end(), value) == patterns.end()) patterns.push_back(value);
            } else domains.insert(value);
        }
        for (const auto& entry : rules["blocked_ports"]) {
            if (!entry.is_number_integer()) throw std::runtime_error("Invalid port rule");
            const auto port = entry.get<int64_t>();
            if (port < 1 || port > 65535) throw std::runtime_error("Port outside 1..65535");
            ports.insert(static_cast<uint16_t>(port));
        }
        // Validate the entire replacement before touching the current policy.
        {
            std::scoped_lock lock(ip_mutex_, app_mutex_, domain_mutex_, port_mutex_);
            blocked_ips_.swap(ips);
            blocked_apps_.swap(apps);
            blocked_domains_.swap(domains);
            domain_patterns_.swap(patterns);
            blocked_ports_.swap(ports);
        }
        if (enforcement_) enforcement_->clearAll();
        std::cout << "[RuleManager] Rules loaded from: " << filename << std::endl;
        return true;
    } catch (const std::exception& error) {
        std::cerr << "[RuleManager] " << error.what() << ". Existing rules retained.\n";
        return false;
    }
}

void RuleManager::clearAll() {
    {
        std::unique_lock<std::shared_mutex> lock(ip_mutex_);
        blocked_ips_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(app_mutex_);
        blocked_apps_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(domain_mutex_);
        blocked_domains_.clear();
        domain_patterns_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(port_mutex_);
        blocked_ports_.clear();
    }
    if (enforcement_) {
        enforcement_->clearAll();
    }
    std::cout << "[RuleManager] All rules cleared" << std::endl;
}

void RuleManager::reinstallAllWfpRules(const std::unordered_map<uint32_t, std::string>& ip_to_domain) {
    if (!enforcement_) return;

    // 1. IP blocks
    {
        std::shared_lock<std::shared_mutex> lock(ip_mutex_);
        for (uint32_t ip : blocked_ips_) {
            enforcement_->blockIP(ip);
        }
    }

    // 2. Port blocks
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        for (uint16_t port : blocked_ports_) {
            enforcement_->blockPort(port);
        }
    }

    // 3. Domain blocks - lookup known IPs from ip_to_domain
    {
        std::shared_lock<std::shared_mutex> lock(domain_mutex_);
        std::vector<std::string> domains(blocked_domains_.begin(), blocked_domains_.end());
        domains.insert(domains.end(), domain_patterns_.begin(), domain_patterns_.end());
        for (const std::string& domain : domains) {
            std::vector<uint32_t> known_ips;
            for (const auto& kv : ip_to_domain) {
                if (kv.second == domain || domainMatchesPattern(kv.second, domain)) {
                    known_ips.push_back(kv.first);
                }
            }
            enforcement_->blockDomain(domain, known_ips);
        }
    }
}

RuleManager::RuleStats RuleManager::getStats() const {
    RuleStats stats;
    
    {
        std::shared_lock<std::shared_mutex> lock(ip_mutex_);
        stats.blocked_ips = blocked_ips_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(app_mutex_);
        stats.blocked_apps = blocked_apps_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(domain_mutex_);
        stats.blocked_domains = blocked_domains_.size() + domain_patterns_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        stats.blocked_ports = blocked_ports_.size();
    }
    
    return stats;
}

} // namespace DPI
