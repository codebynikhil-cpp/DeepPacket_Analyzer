#include "tcp_reassembler.h"
#include "sni_extractor.h"
#include "packet_parser.h"

namespace DPI {

void TcpReassembler::evictOldFlowsUnlocked(const std::chrono::steady_clock::time_point& now) {
    const auto timeout = std::chrono::seconds(FLOW_TIMEOUT_SECONDS);
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (now - it->second.last_seen > timeout) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t TcpReassembler::evictOldFlows() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    size_t before = flows_.size();
    evictOldFlowsUnlocked(now);
    return before - flows_.size();
}

size_t TcpReassembler::activeFlowCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_.size();
}

void TcpReassembler::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    flows_.clear();
}

std::optional<std::string> TcpReassembler::inspectSegment(uint32_t seq,
                                                          uint32_t ack,
                                                          const uint8_t* payload,
                                                          size_t len) {
    // Single-flow signature (Requirement 5) using default key
    TcpFlowKey default_key{0, 0, 0, 443};
    return inspectSegment(default_key.src_ip, default_key.src_port,
                          default_key.dst_ip, default_key.dst_port,
                          seq, ack, payload, len, 0);
}

std::optional<std::string> TcpReassembler::inspectSegment(const PacketAnalyzer::ParsedPacket& pkt) {
    if (!pkt.has_tcp || !pkt.payload_data || pkt.payload_length == 0) {
        return std::nullopt;
    }
    // Only TLS traffic (typically destination port 443)
    if (pkt.dest_port != 443 && pkt.src_port != 443) {
        return std::nullopt;
    }
    return inspectSegment(pkt.src_ip_num, pkt.src_port,
                          pkt.dest_ip_num, pkt.dest_port,
                          pkt.seq_number, pkt.ack_number,
                          pkt.payload_data, pkt.payload_length,
                          pkt.tcp_flags);
}

std::optional<std::string> TcpReassembler::inspectSegment(uint32_t src_ip,
                                                          uint16_t src_port,
                                                          uint32_t dst_ip,
                                                          uint16_t dst_port,
                                                          uint32_t seq,
                                                          uint32_t ack,
                                                          const uint8_t* payload,
                                                          size_t len,
                                                          uint8_t tcp_flags) {
    if (!payload || len == 0) {
        return std::nullopt;
    }

    TcpFlowKey key{src_ip, src_port, dst_ip, dst_port};
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();

    // Clean up expired flows on periodic threshold or buffer count
    if (flows_.size() > 64) {
        evictOldFlowsUnlocked(now);
    }

    return processFlowSegment(key, seq, ack, payload, len, tcp_flags);
}

std::optional<std::string> TcpReassembler::processFlowSegment(const TcpFlowKey& key,
                                                              uint32_t seq,
                                                              uint32_t /*ack*/,
                                                              const uint8_t* payload,
                                                              size_t len,
                                                              uint8_t /*tcp_flags*/) {
    const auto now = std::chrono::steady_clock::now();
    auto it = flows_.find(key);

    if (it != flows_.end()) {
        ReassemblyFlow& flow = it->second;
        flow.last_seen = now;

        // Check sequence continuity
        if (seq == flow.next_seq) {
            // Buffer capacity check (Requirement 4: Cap buffer at 2048 bytes per flow)
            if (flow.buffer.size() + len > MAX_BUFFER_PER_FLOW) {
                flows_.erase(it);
                return std::nullopt;
            }

            flow.buffer.insert(flow.buffer.end(), payload, payload + len);
            flow.next_seq = seq + static_cast<uint32_t>(len);

            // Attempt SNI extraction on reassembled stream
            auto sni = SNIExtractor::extract(flow.buffer.data(), flow.buffer.size());
            if (sni) {
                // Reassembly succeeded, evict flow buffer and return extracted SNI
                flows_.erase(it);
                return sni;
            }

            // If we know the expected total length and we reached it, but no SNI was found, stop buffering
            if (flow.expected_total_len > 0 && flow.buffer.size() >= flow.expected_total_len) {
                flows_.erase(it);
            }
            return std::nullopt;
        }

        // Out of order or retransmission: if buffer size exceeded or sequence disjoint, drop
        if (seq > flow.next_seq + 16384 || flow.buffer.size() + len > MAX_BUFFER_PER_FLOW) {
            flows_.erase(it);
        }
        return std::nullopt;
    }

    // New segment: check if it is the start of a TLS Handshake (0x16 0x03)
    if (len >= 2 && payload[0] == 0x16 && payload[1] == 0x03) {
        // First try single-packet extraction
        auto sni = SNIExtractor::extract(payload, len);
        if (sni) {
            return sni; // Complete in single segment, no reassembly needed
        }

        // Parse record length if available (bytes 3 and 4)
        uint16_t expected_total = 0;
        if (len >= 5) {
            uint16_t record_len = (static_cast<uint16_t>(payload[3]) << 8) | payload[4];
            expected_total = 5 + record_len;
        }

        // Check if segment is incomplete (less than expected total or less than 2048)
        if (len < MAX_BUFFER_PER_FLOW && (expected_total == 0 || len < expected_total)) {
            ReassemblyFlow flow;
            flow.next_seq = seq + static_cast<uint32_t>(len);
            flow.expected_total_len = expected_total;
            flow.buffer.assign(payload, payload + len);
            flow.last_seen = now;
            flows_[key] = std::move(flow);
        }
    }

    return std::nullopt;
}

} // namespace DPI

