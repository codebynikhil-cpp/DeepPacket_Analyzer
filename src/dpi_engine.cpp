#include "dpi_engine.h"
#include "sni_extractor.h"
#include "dns_parser.h"
#include "http_parser.h"

namespace DPI {

AppClassification DPIEngine::inspect(const PacketAnalyzer::ParsedPacket& pkt) {
    AppClassification result;
    
    if (pkt.payload_length == 0 || !pkt.payload_data) {
        return result; 
    }

    if (pkt.has_tcp) {
        if (pkt.src_port == 443 || pkt.dest_port == 443) {
            auto sniOpt = SNIExtractor::extract(pkt.payload_data, pkt.payload_length);
            if (sniOpt) {
                result.method = "TLS SNI";
                result.sni_or_host = *sniOpt;
                result.app = sniToAppType(result.sni_or_host);
                if (result.app == AppType::UNKNOWN) result.app = AppType::HTTPS;
                return result;
            }
            // If TLS SNI is not present, classify as generic HTTPS protocol, no heuristic guessing
            result.app = AppType::HTTPS;
            result.method = "Port 443";
            return result;
        } 
        else if (pkt.src_port == 80 || pkt.dest_port == 80) {
            auto httpOpt = HTTPParser::extract(pkt.payload_data, pkt.payload_length);
            if (httpOpt) {
                result.method = "HTTP Host";
                result.sni_or_host = httpOpt->host;
                result.http_method = httpOpt->method;
                result.http_path = httpOpt->path;
                result.app = sniToAppType(result.sni_or_host);
                if (result.app == AppType::UNKNOWN) result.app = AppType::HTTP;
                return result;
            }
            result.app = AppType::HTTP;
            result.method = "Port 80";
            return result;
        }
    } 
    else if (pkt.has_udp) {
        if (pkt.src_port == 53 || pkt.dest_port == 53) {
            auto dnsOpt = DNSParser::extractQuery(pkt.payload_data, pkt.payload_length);
            if (dnsOpt) {
                result.method = "DNS Query";
                result.sni_or_host = *dnsOpt;
                result.app = sniToAppType(result.sni_or_host);
                if (result.app == AppType::UNKNOWN) result.app = AppType::DNS;
                return result;
            }
            result.app = AppType::DNS;
            result.method = "Port 53";
            return result;
        }
        else if (pkt.src_port == 443 || pkt.dest_port == 443) {
            // QUIC / HTTP/3 traffic
            if (QUICSNIExtractor::isQUICInitial(pkt.payload_data, pkt.payload_length)) {
                result.app = AppType::QUIC;
                result.method = "QUIC v1 Initial";
            }
            return result;
        }
    }
    
    return result;
}


} // namespace DPI
