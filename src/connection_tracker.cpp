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
    std::unordered_map<uint32_t, std::string> plain_ip_domain = dns_cache_.getActiveMappings();
    rule_manager_.reinstallAllWfpRules(plain_ip_domain);
}

void ConnectionTracker::learnDnsMapping(const std::string& domain, uint32_t ip, uint32_t ttl) {
    if (ip == 0 || domain.empty()) return;
    dns_cache_.learnDnsMapping(domain, ip, ttl);
    if (enforcement_) {
        enforcement_->onNewDnsMapping(domain, ip);
    }
}

std::string ConnectionTracker::lookupDomainForIP(uint32_t ip) {
    return dns_cache_.getBestDomainForIP(ip);
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
        dns_cache_.cleanupExpired();
        tcp_reassembler_.evictOldFlows();
        if (connections_.size() > 10000) {
            const auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(5);
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

    // 1b. Segmented TLS stream reassembly fallback (if SNI was not found in single packet)
    if (conn->sni.empty() && pkt.has_tcp && (pkt.src_port == 443 || pkt.dest_port == 443)) {
        auto reassembled = tcp_reassembler_.inspectSegment(pkt);
        if (reassembled) {
            conn->sni = *reassembled;
            conn->app_type = sniToAppType(conn->sni);
            if (conn->app_type == AppType::UNKNOWN) conn->app_type = AppType::HTTPS;
            conn->app_name = resolveAppName(conn->sni);
            conn->detection_method = "TLS SNI";
            conn->state = ConnectionState::CLASSIFIED;
            recordHostnameObservation(conn->sni);
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
            // 2.5. IP-range lookup: catches MTProto, QUIC-direct, etc.
            if (pkt.ip_version == 4) {
                AppType ip_app = ipToAppType(pkt.dest_ip_num);
                if (ip_app == AppType::UNKNOWN) ip_app = ipToAppType(pkt.src_ip_num);
                if (ip_app != AppType::UNKNOWN) {
                    conn->app_type = ip_app;
                    conn->app_name = appTypeToString(ip_app);
                    conn->sni = conn->app_name; // Use app name as display label
                    conn->detection_method = "IP Range";
                    conn->state = ConnectionState::CLASSIFIED;
                }
            }
            // 3. Port-based fallback
            if (conn->app_type == AppType::UNKNOWN) {
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

        recent_flows_.push_back(rec);
        if (recent_flows_.size() > 500) {
            recent_flows_.erase(recent_flows_.begin());
        }
        if (!eval_export_path_.empty()) {
            eval_flows_.push_back(std::move(rec));
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
        if (!eval_export_path_.empty()) {
            for (auto it = eval_flows_.rbegin(); it != eval_flows_.rend(); ++it) {
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

void ConnectionTracker::exportEvaluationFlows(const std::string& path) const {
    const std::string target = path.empty() ? eval_export_path_ : path;
    if (target.empty()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json j;
    j["schema_version"] = 1;
    j["total_evaluation_flows"] = eval_flows_.size();
    nlohmann::json flows_arr = nlohmann::json::array();

    for (const auto& f : eval_flows_) {
        nlohmann::json item;
        item["src_ip"] = f.src_ip;
        item["src_port"] = f.src_port;
        item["dst_ip"] = f.dst_ip;
        item["dst_port"] = f.dst_port;
        item["protocol"] = f.protocol;
        item["domain"] = f.domain;
        item["application"] = f.application;
        item["method"] = f.method;
        item["confidence"] = f.confidence;
        item["policy"] = f.policy;
        item["policy_reason"] = f.policy_reason;
        item["enforcement"] = f.enforcement;
        item["packets"] = f.packets;
        item["bytes"] = f.bytes;
        flows_arr.push_back(item);
    }
    j["flows"] = flows_arr;

    std::ofstream out(target, std::ios::trunc);
    if (out.is_open()) {
        out << j.dump(2) << "\n";
        out.close();
        std::cout << "[Evaluation] Exported " << eval_flows_.size() 
                  << " unevicted flow records to " << target << std::endl;
    } else {
        std::cerr << "[Evaluation] Error: Could not write evaluation flows to " << target << std::endl;
    }
}

void ConnectionTracker::exportEvaluationFlowsToCsv(const std::string& csv_path) const {
    if (csv_path.empty()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream out(csv_path, std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "[Evaluation] Error: Could not write CSV to " << csv_path << std::endl;
        return;
    }

    out << "flow_id,src_ip,src_port,dst_ip,dst_port,protocol,domain,application,method,confidence,policy,packets,bytes\n";
    size_t id = 1;
    for (const auto& f : eval_flows_) {
        out << id++ << ","
            << f.src_ip << ","
            << f.src_port << ","
            << f.dst_ip << ","
            << f.dst_port << ","
            << f.protocol << ","
            << "\"" << f.domain << "\","
            << "\"" << f.application << "\","
            << "\"" << f.method << "\","
            << f.confidence << ","
            << f.policy << ","
            << f.packets << ","
            << f.bytes << "\n";
    }
    out.close();
    std::cout << "[Evaluation] Exported " << eval_flows_.size() 
              << " flow records to CSV: " << csv_path << std::endl;
}

} // namespace DPI
