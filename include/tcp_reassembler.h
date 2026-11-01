#ifndef TCP_REASSEMBLER_H
#define TCP_REASSEMBLER_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <mutex>

namespace PacketAnalyzer {
struct ParsedPacket;
}

namespace DPI {

// 4-Tuple key tracking TCP flow direction (client -> server)
struct TcpFlowKey {
    uint32_t src_ip = 0;
    uint16_t src_port = 0;
    uint32_t dst_ip = 0;
    uint16_t dst_port = 0;

    bool operator==(const TcpFlowKey& other) const {
        return src_ip == other.src_ip &&
               src_port == other.src_port &&
               dst_ip == other.dst_ip &&
               dst_port == other.dst_port;
    }
};

struct TcpFlowKeyHash {
    size_t operator()(const TcpFlowKey& k) const {
        size_t h1 = std::hash<uint32_t>{}(k.src_ip);
        size_t h2 = std::hash<uint16_t>{}(k.src_port);
        size_t h3 = std::hash<uint32_t>{}(k.dst_ip);
        size_t h4 = std::hash<uint16_t>{}(k.dst_port);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};

// Reassembly buffer state for a flow
struct ReassemblyFlow {
    uint32_t next_seq = 0;
    uint16_t expected_total_len = 0;
    std::vector<uint8_t> buffer;
    std::chrono::steady_clock::time_point last_seen;
};

// Minimal TCP Stream Reassembler specialized for segmented TLS Client Hello messages
class TcpReassembler {
public:
    static constexpr size_t MAX_BUFFER_PER_FLOW = 2048; // Max 2KB buffer per flow
    static constexpr int FLOW_TIMEOUT_SECONDS = 5;      // Evict after 5 seconds

    TcpReassembler() = default;
    ~TcpReassembler() = default;

    TcpReassembler(const TcpReassembler&) = delete;
    TcpReassembler& operator=(const TcpReassembler&) = delete;

    // Requirement 5 interface: Single-flow inspectSegment
    std::optional<std::string> inspectSegment(uint32_t seq,
                                              uint32_t ack,
                                              const uint8_t* payload,
                                              size_t len);

    // Requirement 1 & 2 full flow-tracking interface
    std::optional<std::string> inspectSegment(uint32_t src_ip,
                                              uint16_t src_port,
                                              uint32_t dst_ip,
                                              uint16_t dst_port,
                                              uint32_t seq,
                                              uint32_t ack,
                                              const uint8_t* payload,
                                              size_t len,
                                              uint8_t tcp_flags = 0);

    // Helper to inspect directly from a ParsedPacket
    std::optional<std::string> inspectSegment(const PacketAnalyzer::ParsedPacket& pkt);

    // Evicts flows idle for longer than 5 seconds
    size_t evictOldFlows();

    // Active flows count
    size_t activeFlowCount() const;

    // Reset all state
    void clear();

private:
    mutable std::mutex mutex_;
    std::unordered_map<TcpFlowKey, ReassemblyFlow, TcpFlowKeyHash> flows_;

    std::optional<std::string> processFlowSegment(const TcpFlowKey& key,
                                                  uint32_t seq,
                                                  uint32_t ack,
                                                  const uint8_t* payload,
                                                  size_t len,
                                                  uint8_t tcp_flags);

    void evictOldFlowsUnlocked(const std::chrono::steady_clock::time_point& now);
};

} // namespace DPI

#endif // TCP_REASSEMBLER_H

