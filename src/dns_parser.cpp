#include "dns_parser.h"
#include <cstring>

namespace DPI {

bool DNSParser::isDNSQuery(const uint8_t* payload, size_t length) {
    if (!payload || length < 12) return false;
    
    // Check QR bit (byte 2, bit 7) - should be 0 for query
    uint8_t flags = payload[2];
    if (flags & 0x80) return false;
    
    // Check QDCOUNT (bytes 4-5) - should be > 0
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (qdcount == 0) return false;
    
    return true;
}

std::optional<std::string> DNSParser::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) {
        return std::nullopt;
    }
    
    // DNS query starts at byte 12
    size_t offset = 12;
    std::string domain;
    
    while (offset < length) {
        uint8_t label_length = payload[offset];
        
        if (label_length == 0) {
            return offset + 5 <= length && !domain.empty() ? std::optional<std::string>(domain) : std::nullopt;
        }
        
        if (label_length > 63) {
            return std::nullopt; // Compression pointer or invalid
        }
        
        offset++;
        if (offset + label_length > length || domain.size() + label_length + 1 > 253) return std::nullopt;
        
        if (!domain.empty()) {
            domain += '.';
        }
        domain += std::string(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    
    return std::nullopt;
}

// Skip over a DNS name (handles compression pointers)
// Returns new offset, or 0 on error
size_t DNSParser::skipName(const uint8_t* payload, size_t length, size_t offset) {
    while (offset < length) {
        uint8_t len = payload[offset];
        if (len == 0) {
            return offset + 1; // end of name
        }
        if ((len & 0xC0) == 0xC0) {
            // Compression pointer: 2 bytes total
            return offset + 2 <= length ? offset + 2 : 0;
        }
        if (len > 63 || offset + 1 + len > length) return 0;
        offset += 1 + len;
    }
    return 0; // error
}

// Parse DNS response and extract all A-record (IPv4) answers
std::vector<DnsAnswer> DNSParser::extractAnswers(const uint8_t* payload, size_t length) {
    std::vector<DnsAnswer> results;
    if (length < 12) return results;

    // Check QR bit must be 1 (response)
    if (!(payload[2] & 0x80)) return results;

    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    uint16_t ancount = (static_cast<uint16_t>(payload[6]) << 8) | payload[7];
    if (ancount == 0) return results;

    // Extract the question's domain name (used to label answers)
    size_t offset = 12;
    std::string qname;
    while (offset < length) {
        uint8_t llen = payload[offset];
        if (llen == 0) { offset++; break; }
        if ((llen & 0xC0) == 0xC0) { if (offset + 2 > length) return results; offset += 2; break; }
        if (llen > 63 || offset + 1 + llen > length) return results;
        if (!qname.empty()) qname += '.';
        qname += std::string(reinterpret_cast<const char*>(payload + offset + 1), llen);
        offset += 1 + llen;
    }
    // Skip QTYPE + QCLASS (4 bytes)
    if (offset + 4 > length) return results;
    offset += 4;

    // Parse answer records
    for (int i = 0; i < ancount && offset < length; i++) {
        // Skip the NAME field in each RR (can be a pointer)
        size_t new_offset = skipName(payload, length, offset);
        if (new_offset == 0 || new_offset + 10 > length) break;
        offset = new_offset;

        uint16_t rtype  = (static_cast<uint16_t>(payload[offset])   << 8) | payload[offset+1];
        // uint16_t rclass = (static_cast<uint16_t>(payload[offset+2]) << 8) | payload[offset+3];
        uint32_t ttl    = (static_cast<uint32_t>(payload[offset+4]) << 24) |
                          (static_cast<uint32_t>(payload[offset+5]) << 16) |
                          (static_cast<uint32_t>(payload[offset+6]) << 8)  |
                          payload[offset+7];
        uint16_t rdlen  = (static_cast<uint16_t>(payload[offset+8]) << 8) | payload[offset+9];
        offset += 10;

        if (offset + rdlen > length) break;

        // Type A = 1 (IPv4 address)
        if (rtype == 1 && rdlen == 4) {
            uint32_t ip;
            std::memcpy(&ip, payload + offset, 4);
            if (!qname.empty()) {
                results.push_back({qname, ip, ttl});
            }
        }
        offset += rdlen;

    }

    return results;
}

} // namespace DPI
