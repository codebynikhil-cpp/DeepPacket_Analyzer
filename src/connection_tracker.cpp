#include "connection_tracker.h"
#include "dns_parser.h"
#include "types.h"
#include "wfp_enforcement.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <fstream>
#include <ctime>
#include "vendor/nlohmann/json.hpp"

namespace DPI {

// Helper to format a domain name into a clean display title
static std::string formatDomainAsApp(const std::string& domain) {
    if (domain.empty()) return "";
    
    std::string s = domain;
    size_t colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(0, colon);

    if (s.rfind("www.", 0) == 0) s = s.substr(4);

    return s;
}

void ConnectionTracker::loadCriticalWebsites(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;

    try {
        const auto config = nlohmann::json::parse(file);
        std::vector<std::pair<std::string, std::vector<std::string>>> sites;
        for (const auto& site : config.at("websites")) {
            sites.emplace_back(site.at("name").get<std::string>(), site.at("domains").get<std::vector<std::string>>());
        }
        critical_websites_.swap(sites);
    } catch (const std::exception& error) {
        std::cerr << "[Configuration] Invalid website registry: " << error.what() << "\n";
    }
}

std::string ConnectionTracker::resolveAppName(const std::string& domain) const {
    if (domain.empty()) return "UNKNOWN";

    // 1. Match configured critical websites registry
    for (const auto& cw : critical_websites_) {
        for (const auto& pat : cw.second) {
            if (WfpEnforcement::domainMatches(domain, pat)) {
                return cw.first;
            }
        }
    }

    // 2. Match known AppType enum table
    AppType at = sniToAppType(domain);
    if (at != AppType::UNKNOWN && at != AppType::HTTPS && at != AppType::HTTP && at != AppType::TLS && at != AppType::QUIC && at != AppType::DNS) {
        return appTypeToString(at);
    }

    // 3. Fallback: formatted domain as application title
    return formatDomainAsApp(domain);
}

std::map<std::string, size_t> ConnectionTracker::getApplicationStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, size_t> stats = observed_applications_;
    for (const auto& pair : connections_) {
        const auto& conn = pair.second;
        // Named traffic is counted when its hostname is observed. Keep unnamed
        // protocol traffic visible without counting named flows a second time.
        if (conn.sni.empty()) {
            stats[appTypeToString(conn.app_type)]++;
        }
    }
    return stats;
}

std::map<std::string, size_t> ConnectionTracker::getDomainStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return observed_domains_;
}

ConnectionTracker::ConnectionTracker() {
    loadCriticalWebsites("critical_websites.json");
}

void ConnectionTracker::recordHostnameObservation(const std::string& domain) {
    if (domain.empty()) return;
    std::string normalized = domain;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!normalized.empty() && normalized.back() == '.') normalized.pop_back();
    if (normalized.empty()) return;

    constexpr size_t observation_limit = 4096;
    auto domain_it = observed_domains_.find(normalized);
    if (domain_it != observed_domains_.end()) ++domain_it->second;
    else if (observed_domains_.size() < observation_limit) observed_domains_.emplace(normalized, 1);

    const std::string application = resolveAppName(normalized);
    auto app_it = observed_applications_.find(application);
    if (app_it != observed_applications_.end()) ++app_it->second;
    else if (observed_applications_.size() < observation_limit) observed_applications_.emplace(application, 1);
}

void ConnectionTracker::setEnforcement(WfpEnforcement* enforcement) {
    enforcement_ = enforcement;
    rule_manager_.setEnforcement(enforcement);
}

void ConnectionTracker::reinstallWfpRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<uint32_t, std::string> plain_ip_domain;
    auto now = std::chrono::steady_clock::now();
    for (const auto& kv : ip_to_domain_) {
        if (kv.second.expires_at > now) {
            plain_ip_domain[kv.first] = kv.second.domain;
        }
    }
    rule_manager_.reinstallAllWfpRules(plain_ip_domain);
}

void ConnectionTracker::learnDnsMapping(const std::string& domain, uint32_t ip, uint32_t ttl) {
    if (ip == 0 || domain.empty()) return;
    if (ttl == 0) ttl = 300; // minimum default 5 min
    auto expires = std::chrono::steady_clock::now() + std::chrono::seconds(ttl);
    if (ip_to_domain_.size() >= 16384 && ip_to_domain_.find(ip) == ip_to_domain_.end())
        ip_to_domain_.erase(ip_to_domain_.begin());
    ip_to_domain_[ip] = { domain, ttl, expires };
    if (enforcement_) {
        enforcement_->onNewDnsMapping(domain, ip);
    }
}

std::string ConnectionTracker::lookupDomainForIP(uint32_t ip) {
    auto it = ip_to_domain_.find(ip);
    if (it != ip_to_domain_.end()) {
        if (it->second.expires_at > std::chrono::steady_clock::now()) {
            return it->second.domain;
        }
    }
    return "";
}

Connection* ConnectionTracker::getOrCreateConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        return &it->second;
    }
    auto rev_it = connections_.find(tuple.reverse());
    if (rev_it != connections_.end()) {
        return &rev_it->second;
    }
    
    // Keep tracker memory bounded even when all observed flows are recent.
    if (connections_.size() >= 10000) connections_.erase(connections_.begin());
    Connection conn;
    conn.tuple = tuple;
    conn.state = ConnectionState::NEW;
    conn.first_seen = std::chrono::steady_clock::now();
    conn.last_seen = conn.first_seen;
    auto result = connections_.emplace(tuple, std::move(conn));
    return &result.first->second;
}

static std::string ipNumToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

static std::string getNowTimestamp() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%H:%M:%S");
    return oss.str();
}

static void appendRecent(std::vector<std::string>& items, const std::string& value) {
    items.push_back(value);
    if (items.size() > 100) items.erase(items.begin());
}

PacketAction ConnectionTracker::process(const PacketAnalyzer::ParsedPacket& pkt,
                                        const std::optional<AppClassification>& classification) {
    if (!pkt.has_ip) return PacketAction::FORWARD;
    std::lock_guard<std::mutex> lock(mutex_);
    total_seen_++;
    if (total_seen_ % 1000 == 0) {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = ip_to_domain_.begin(); it != ip_to_domain_.end();) {
            if (it->second.expires_at <= now) it = ip_to_domain_.erase(it);
            else ++it;
        }
        if (connections_.size() > 10000) {
            const auto cutoff = now - std::chrono::minutes(5);
            for (auto it = connections_.begin(); it != connections_.end();) {
                if (it->second.last_seen < cutoff) it = connections_.erase(it);
                else ++it;
            }
        }
    }
    
    FiveTuple tuple;
    tuple.src_ip = pkt.src_ip;
    tuple.dst_ip = pkt.dest_ip;
    tuple.src_port = pkt.src_port;
    tuple.dst_port = pkt.dest_port;
    tuple.protocol = pkt.protocol;
    
    Connection* conn = getOrCreateConnection(tuple);
    const bool is_new_flow = conn->state == ConnectionState::NEW;
    conn->last_seen = std::chrono::steady_clock::now();
    if (tuple == conn->tuple) { ++conn->packets_out; conn->bytes_out += pkt.frame_length; }
    else { ++conn->packets_in; conn->bytes_in += pkt.frame_length; }
    
    // Check for suspicious ports once per new connection
    if (is_new_flow) {
        if (pkt.src_port == 4444 || pkt.dest_port == 4444) {
            std::string msg = "Suspicious port 4444";
            appendRecent(alerts_, msg);
        }
        if (pkt.src_port == 1337 || pkt.dest_port == 1337) {
            std::string msg = "Suspicious port 1337";
            appendRecent(alerts_, msg);
        }
    }

    // 1. Structured inspection of visible TLS, HTTP, and DNS names.
    if (classification.has_value()) {
        if (!classification->sni_or_host.empty()) {
            conn->sni = classification->sni_or_host;
            conn->app_type = classification->app;
            conn->app_name = resolveAppName(conn->sni);
            recordHostnameObservation(conn->sni);
            
            if (pkt.has_tcp && (pkt.src_port == 443 || pkt.dest_port == 443)) {
                conn->detection_method = "TLS SNI";
            } else if (pkt.has_tcp && (pkt.src_port == 80 || pkt.dest_port == 80)) {
                conn->detection_method = "HTTP Host";
            } else if (pkt.has_udp && (pkt.src_port == 53 || pkt.dest_port == 53)) {
                conn->detection_method = "DNS Query";
            }
            conn->state = ConnectionState::CLASSIFIED;
        } else if (conn->app_type == AppType::UNKNOWN && classification->app != AppType::UNKNOWN) {
            conn->app_type = classification->app;
            conn->detection_method = classification->method;
            conn->state = ConnectionState::CLASSIFIED;
        }
        
        // Process DNS payload responses & learn IP mappings with TTL
        if ((pkt.src_port == 53 || pkt.dest_port == 53) && pkt.payload_data) {
            if (pkt.has_udp && pkt.dest_port == 53 && !conn->sni.empty()) {
                appendRecent(dns_queries_, conn->sni);
            }
            auto answers = DNSParser::extractAnswers(pkt.payload_data, pkt.payload_length);
            for (const auto& ans : answers) {
                learnDnsMapping(ans.domain, ans.ip, ans.ttl);
                if (!ans.domain.empty()) {
                    bool already = false;
                    for (const auto& q : dns_queries_) {
                        if (q == ans.domain) { already = true; break; }
                    }
                    if (!already) {
                        recordHostnameObservation(ans.domain);
                        appendRecent(dns_queries_, ans.domain);
                    }
                }
            }
        }
        
        // Output HTTP requests in real-time list
        if (!classification->http_method.empty()) {
            std::string req = classification->http_method + " " + classification->sni_or_host + classification->http_path;
            appendRecent(http_requests_, req);
        }
    }

    // 2. DNS Correlation Fallback (if no SNI was directly extracted on this packet)
    if (conn->sni.empty()) {
        std::string resolved = pkt.ip_version == 4 ? lookupDomainForIP(pkt.dest_ip_num) : "";
        if (resolved.empty() && pkt.ip_version == 4) resolved = lookupDomainForIP(pkt.src_ip_num);
        if (!resolved.empty()) {
            conn->sni = resolved;
            conn->app_name = resolveAppName(resolved);
            const auto mapped_app = sniToAppType(resolved);
            if (mapped_app != AppType::UNKNOWN) conn->app_type = mapped_app;
            conn->detection_method = "DNS Correlation";
            conn->state = ConnectionState::CLASSIFIED;
        } else if (conn->app_type == AppType::UNKNOWN) {
            if (pkt.dest_port == 443 || pkt.src_port == 443) {
                conn->app_type = pkt.has_udp ? AppType::UNKNOWN : AppType::HTTPS;
                conn->detection_method = "Port 443";
            } else if (pkt.dest_port == 80 || pkt.src_port == 80) {
                conn->app_type = AppType::HTTP;
                conn->detection_method = "Port 80";
            } else if (pkt.dest_port == 53 || pkt.src_port == 53) {
                conn->app_type = AppType::DNS;
                conn->detection_method = "Port 53";
            }
        }
    }
    
    // Check Rules dynamically (IP, App, Domain, Port)
    bool blocked = false;
    std::string policy_reason;
    if (pkt.ip_version == 4) {
        const auto match = rule_manager_.shouldBlock(pkt.src_ip_num, pkt.dest_port, conn->app_type, conn->sni);
        if (match) policy_reason = match->detail;
    } else {
        if (rule_manager_.isPortBlocked(pkt.dest_port)) policy_reason = "Destination port " + std::to_string(pkt.dest_port);
        else if (rule_manager_.isAppBlocked(conn->app_type)) policy_reason = "Application " + appTypeToString(conn->app_type);
        else if (rule_manager_.isDomainBlocked(conn->sni)) policy_reason = "Domain " + conn->sni;
    }
    if (policy_reason.empty() && rule_manager_.isPortBlocked(pkt.src_port)) policy_reason = "Source port " + std::to_string(pkt.src_port);
    if (policy_reason.empty() && pkt.ip_version == 4 && rule_manager_.isIPBlocked(pkt.dest_ip_num)) policy_reason = "Destination IP " + pkt.dest_ip;
    if (!policy_reason.empty()) {
        conn->action = PacketAction::DROP;
        blocked = true;
    } else {
        conn->action = PacketAction::FORWARD;
    }
    
    if (conn->action == PacketAction::DROP) {
        dropped_count_++;
    }

    // Record flow for Dashboard recent-flows table once per new connection
    if (is_new_flow) {
        FlowRecord rec;
        rec.timestamp = getNowTimestamp();
        rec.packets = conn->packets_in + conn->packets_out;
        rec.bytes = conn->bytes_in + conn->bytes_out;
        rec.first_seen_us = rec.last_seen_us = static_cast<uint64_t>(pkt.timestamp_sec) * 1000000 + pkt.timestamp_usec;
        rec.src_ip = tuple.src_ip;
        rec.src_port = tuple.src_port;
        rec.dst_ip = tuple.dst_ip;
        rec.dst_port = tuple.dst_port;
        rec.protocol = PacketAnalyzer::PacketParser::protocolToString(tuple.protocol);
        rec.domain = conn->sni.empty() ? "UNKNOWN" : conn->sni;
        rec.application = conn->app_name.empty() ? appTypeToString(conn->app_type) : conn->app_name;
        rec.method = conn->detection_method;
        rec.confidence = (rec.method == "TLS SNI" || rec.method == "HTTP Host") ? "high" :
                         (rec.method == "DNS Correlation" || rec.method == "DNS Query") ? "medium" : "low";
        rec.policy_reason = policy_reason;
        rec.policy = blocked ? "DROP" : "FORWARD";
        rec.enforcement = (enforcement_ && enforcement_->isActive()) ? "WFP ACTIVE" : "MONITOR ONLY";

        recent_flows_.push_back(std::move(rec));
        if (recent_flows_.size() > 100) {
            recent_flows_.erase(recent_flows_.begin());
        }
        if (conn->state == ConnectionState::NEW) conn->state = ConnectionState::ESTABLISHED;
    } else {
        // A ClientHello or DNS answer can arrive after the first packet. Keep the
        // dashboard record in sync with the current classification and rule match.
        for (auto it = recent_flows_.rbegin(); it != recent_flows_.rend(); ++it) {
            if (it->src_ip == conn->tuple.src_ip && it->dst_ip == conn->tuple.dst_ip &&
                it->src_port == conn->tuple.src_port && it->dst_port == conn->tuple.dst_port &&
                it->protocol == PacketAnalyzer::PacketParser::protocolToString(conn->tuple.protocol)) {
                it->packets = conn->packets_in + conn->packets_out;
                it->bytes = conn->bytes_in + conn->bytes_out;
                it->last_seen_us = static_cast<uint64_t>(pkt.timestamp_sec) * 1000000 + pkt.timestamp_usec;
                it->domain = conn->sni.empty() ? "UNKNOWN" : conn->sni;
                it->application = conn->app_name.empty() ? appTypeToString(conn->app_type) : conn->app_name;
                it->method = conn->detection_method;
                it->confidence = (it->method == "TLS SNI" || it->method == "HTTP Host") ? "high" :
                                 (it->method == "DNS Correlation" || it->method == "DNS Query") ? "medium" : "low";
                it->policy_reason = policy_reason;
                it->policy = blocked ? "DROP" : "FORWARD";
                break;
            }
        }
    }

    
    return conn->action;
}

void ConnectionTracker::generateReport() {
    std::map<std::string, size_t> app_distribution = getApplicationStats();

    std::cout << "\n+--------------------------------------------------------------+\n";
    std::cout << "|               CONNECTION STATISTICS REPORT                   |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    std::cout << "| Total Packets Processed:" << std::setw(10) << total_seen_ << "                          |\n";
    std::cout << "| Packets Dropped:        " << std::setw(10) << dropped_count_ << "                          |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    std::cout << "|                    APPLICATION BREAKDOWN                     |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    
    std::vector<std::pair<std::string, size_t>> sorted_apps(app_distribution.begin(), app_distribution.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    
    size_t total_conns = connections_.size();
    for (const auto& pair : sorted_apps) {
        double pct = total_conns > 0 ? (100.0 * pair.second / total_conns) : 0;
        int bar = static_cast<int>(pct / 5);
        std::string bar_str(bar, '#');
        std::string display_name = pair.first;
        if (display_name.length() > 20) {
            display_name = display_name.substr(0, 17) + "...";
        }
        std::cout << "| " << std::setw(20) << std::left << display_name
                  << std::setw(8) << std::right << pair.second
                  << " (" << std::fixed << std::setprecision(1) << std::setw(5) << pct << "%) "
                  << std::setw(14) << std::left << bar_str << " |\n";
    }
    std::cout << "+--------------------------------------------------------------+\n";
}

} // namespace DPI
