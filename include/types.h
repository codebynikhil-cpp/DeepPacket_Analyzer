#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <vector>
#include <atomic>
#include <optional>

namespace DPI {

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow
// ============================================================================
struct FiveTuple {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;  // TCP=6, UDP=17
    
    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    // Create reverse tuple (for matching bidirectional flows)
    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }
    
    std::string toString() const;
};

// Hash function for FiveTuple (used for load balancing)
struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const {
        // Simple but effective hash combining all fields
        size_t h = 0;
        h ^= std::hash<std::string>{}(tuple.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(tuple.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(tuple.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(tuple.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(tuple.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Specific applications (detected via SNI / Host / DNS)
    // Search Engines & Big Tech
    GOOGLE,
    MICROSOFT,
    APPLE,
    AMAZON,
    CLOUDFLARE,
    
    // Social & Messaging
    FACEBOOK,
    INSTAGRAM,
    WHATSAPP,
    TWITTER,
    TELEGRAM,
    TIKTOK,
    DISCORD,
    REDDIT,
    LINKEDIN,
    SNAPCHAT,
    PINTEREST,
    
    // Video & Streaming & Media
    YOUTUBE,
    NETFLIX,
    SPOTIFY,
    TWITCH,
    DISNEYPLUS,
    HULU,
    SOUNDCLOUD,
    
    // AI, Productivity & Collaboration
    OPENAI,
    NOTION,
    ZOOM,
    SLACK,
    TEAMS,
    CANVA,
    FIGMA,
    TRELLO,
    
    // Developer & Tech / Learning Platforms
    GITHUB,
    GITLAB,
    BITBUCKET,
    STACKOVERFLOW,
    LEETCODE,
    WIKIPEDIA,
    COURSERA,
    MEDIUM,

    NPM,
    DOCKER,
    HUGGINGFACE,
    KAGGLE,
    GEEKSFORGEEKS,
    CODECHEF,
    HACKERRANK,
    
    // Gaming & Entertainment
    STEAM,
    ROBLOX,
    EPICGAMES,
    RIOTGAMES,
    
    // E-Commerce & Services
    EBAY,
    ALIEXPRESS,
    PAYPAL,
    UBER,
    
    // Add more as needed
    APP_COUNT  // Keep this last for counting
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

struct AppClassification {
    AppType app = AppType::UNKNOWN;
    std::string method = "Unknown";
    std::string sni_or_host = "";
    std::string http_method = "";
    std::string http_path = "";
};

// ============================================================================
// Connection State
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

// ============================================================================
// Packet Action (what to do with the packet)
// ============================================================================
enum class PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
};

struct FlowRecord {
    uint64_t packets = 0, bytes = 0, first_seen_us = 0, last_seen_us = 0;
    std::string timestamp;
    std::string src_ip;
    uint16_t    src_port = 0;
    std::string dst_ip;
    uint16_t    dst_port = 0;
    std::string protocol;       // "TCP", "UDP", "ICMP"
    std::string domain;         // e.g. "github.com", "unstop.com", "UNKNOWN"
    std::string application;    // e.g. "GitHub", "Unstop", "UNKNOWN"
    std::string method;         // "TLS SNI", "HTTP Host", "DNS Correlation", "Port Heuristic"
    std::string confidence;     // Evidence strength, not a calibrated probability
    std::string policy_reason;  // Rule or heuristic that matched
    std::string policy;         // "FORWARD", "DROP"
    std::string enforcement;    // "WFP ACTIVE", "MONITOR ONLY"
};

// ============================================================================
// Connection Entry (tracked per flow)
// ============================================================================
struct Connection {
    FiveTuple tuple;
    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;             // Server Name Indication / Domain (if detected)
    std::string app_name;        // Resolved friendly app name (e.g. "GitHub")
    std::string detection_method = "Port Heuristic"; // "TLS SNI", "HTTP Host", "DNS Correlation", "Port Heuristic"
    std::string enforcement_state = "MONITOR ONLY";
    
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    PacketAction action = PacketAction::FORWARD;
    
    // For TCP state tracking
    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool fin_seen = false;
};


// ============================================================================
// Packet wrapper for queue passing
// ============================================================================
struct PacketJob {
    uint32_t packet_id;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    uint8_t tcp_flags = 0;
    const uint8_t* payload_data = nullptr;
    
    // Timestamps
    uint32_t ts_sec;
    uint32_t ts_usec;
};

// ============================================================================
// Statistics - uses regular uint64_t, protected by mutex externally
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};
    
    // Non-copyable due to atomics
    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI

#endif // DPI_TYPES_H
