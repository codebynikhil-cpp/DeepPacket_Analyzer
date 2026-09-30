#include "sni_extractor.h"
#include <cstring>
#include <algorithm>

namespace DPI {

// ============================================================================
// TLS SNI Extractor Implementation
// ============================================================================

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    // Minimum TLS record: 5 bytes header + 4 bytes handshake header
    if (length < 9) return false;
    
    // Check TLS record header
    // Byte 0: Content Type (should be 0x16 = Handshake)
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    // Bytes 1-2: TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    // We accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    // Bytes 3-4: Record length
    uint16_t record_length = readUint16BE(payload + 3);
    if (record_length < 4 || record_length > length - 5) return false;
    
    // Check handshake header (starts at byte 5)
    // Byte 5: Handshake Type (should be 0x01 = Client Hello)
    if (payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    
    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    const size_t record_end = 5 + readUint16BE(payload + 3);
    // Skip TLS record header (5 bytes)
    size_t offset = 5;
    
    // Skip handshake header
    // Byte 0: Handshake type (already checked)
    // Bytes 1-3: Length
    uint32_t handshake_length = readUint24BE(payload + offset + 1);
    offset += 4;
    if (handshake_length > record_end - offset) return std::nullopt;
    const size_t handshake_end = offset + handshake_length;
    if (offset + 34 > handshake_end) return std::nullopt;
    
    // Client Hello body
    // Bytes 0-1: Client version
    offset += 2;
    
    // Bytes 2-33: Random (32 bytes)
    offset += 32;
    
    // Session ID
    if (offset >= handshake_end) return std::nullopt;
    uint8_t session_id_length = payload[offset];
    offset += 1 + session_id_length;
    if (offset > handshake_end) return std::nullopt;
    
    // Cipher suites
    if (offset + 2 > handshake_end) return std::nullopt;
    uint16_t cipher_suites_length = readUint16BE(payload + offset);
    offset += 2 + cipher_suites_length;
    if (offset > handshake_end) return std::nullopt;
    
    // Compression methods
    if (offset >= handshake_end) return std::nullopt;
    uint8_t compression_methods_length = payload[offset];
    offset += 1 + compression_methods_length;
    if (offset > handshake_end) return std::nullopt;
    
    // Extensions
    if (offset + 2 > handshake_end) return std::nullopt;
    uint16_t extensions_length = readUint16BE(payload + offset);
    offset += 2;
    
    size_t extensions_end = offset + extensions_length;
    if (extensions_end > handshake_end) return std::nullopt;
    
    // Parse extensions to find SNI
    while (offset + 4 <= extensions_end) {
        uint16_t extension_type = readUint16BE(payload + offset);
        uint16_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (offset + extension_length > extensions_end) break;
        
        if (extension_type == EXTENSION_SNI) {
            // SNI extension found
            // Structure:
            //   SNI List Length (2 bytes)
            //   SNI Type (1 byte) - 0x00 for hostname
            //   SNI Length (2 bytes)
            //   SNI Value (variable)
            
            if (extension_length < 5) break;
            
            uint16_t sni_list_length = readUint16BE(payload + offset);
            if (sni_list_length < 3 || sni_list_length + 2 > extension_length) break;
            
            uint8_t sni_type = payload[offset + 2];
            uint16_t sni_length = readUint16BE(payload + offset + 3);
            
            if (sni_type != SNI_TYPE_HOSTNAME) break;
            if (sni_length > extension_length - 5 || sni_length + 3 > sni_list_length) break;
            
            // Extract the hostname
            std::string sni(reinterpret_cast<const char*>(payload + offset + 5), sni_length);
            return sni;
        }
        
        offset += extension_length;
    }
    
    return std::nullopt;
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t* payload, size_t length) {
    
    std::vector<std::pair<uint16_t, std::string>> extensions;
    
    // Similar parsing logic as extract(), but collect all extensions
    // ... (abbreviated for brevity)
    
    return extensions;
}





// ============================================================================
// QUIC v1 Initial detector; SNI extraction is currently unsupported.
// ============================================================================

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (!payload || length < 6) return false;
    
    // QUIC long header starts with 1 bit set (form bit)
    // and the type should be Initial (0x00)
    uint8_t first_byte = payload[0];
    
    // Long header form
    if ((first_byte & 0x80) == 0) return false;
    
    // Check for QUIC version (bytes 1-4)
    // Common versions: 0x00000001 (v1), 0xff000000+ (drafts)
    // We'll be lenient here
    
    return (first_byte & 0xf0) == 0xc0 &&
           payload[1] == 0 && payload[2] == 0 && payload[3] == 0 && payload[4] == 1;
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    // QUIC Initial packets contain the TLS Client Hello inside CRYPTO frames
    // This is complex to parse properly due to QUIC framing
    // For now, we'll do a simplified search for the SNI extension pattern
    
    if (!isQUICInitial(payload, length)) {
        return std::nullopt;
    }
    
    // QUIC Initial payloads are protected. A byte scan cannot recover SNI.
    // Return unknown until packet protection is removed properly.
    return std::nullopt;
}

} // namespace DPI
