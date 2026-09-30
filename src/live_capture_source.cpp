#include "live_capture_source.h"
#include "pcap_wrapper.h"
#include <iostream>
#include <cctype>

namespace PacketAnalyzer {

LiveCaptureSource::LiveCaptureSource(const std::string& device_name_or_index)
    : input_spec_(device_name_or_index), resolved_device_(device_name_or_index), display_name_(device_name_or_index) {
}

LiveCaptureSource::~LiveCaptureSource() {
    close();
}

bool LiveCaptureSource::open() {
    close();

#ifndef HAVE_NATIVE_PCAP_H
    if (!PcapLoader::init()) {
        std::cerr << "[LiveCapture] Error: Npcap / libpcap DLL is missing or not installed." << std::endl;
        std::cerr << "              Please install Npcap (Windows) or libpcap-dev (Linux/macOS)." << std::endl;
        return false;
    }
#endif

    // Resolve index numbers if input is a digit string (e.g. "1", "2")
    bool is_index = !input_spec_.empty();
    for (char c : input_spec_) {
        if (!std::isdigit(c)) { is_index = false; break; }
    }

    if (is_index) {
        int target_idx = std::stoi(input_spec_);
        auto ifaces = listInterfaces();
        bool found = false;
        for (const auto& iface : ifaces) {
            if (iface.index == target_idx) {
                resolved_device_ = iface.name;
                display_name_ = iface.description.empty() ? "Interface #" + input_spec_ : iface.description;
                std::cout << "[LiveCapture] Selected Interface #" << target_idx 
                          << ": " << iface.description << " (" << iface.name << ")" << std::endl;
                found = true;
                break;
            }
        }
        if (!found) {
            std::cerr << "[LiveCapture] Error: Interface index #" << target_idx << " not found." << std::endl;
            return false;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 100; // 100ms read timeout to allow periodic shutdown check

    handle_ = pcap_open_live(resolved_device_.c_str(), snaplen, promisc, to_ms, errbuf);
    if (!handle_) {
        std::cerr << "[LiveCapture] Error opening device '" << resolved_device_ << "': " << errbuf << std::endl;
        std::cerr << "              (Check root / Administrator permissions)" << std::endl;
        return false;
    }
    if (pcap_datalink(handle_) != 1) {
        std::cerr << "[LiveCapture] Unsupported link type. This version parses Ethernet frames only.\n";
        close();
        return false;
    }

    running_ = true;
    std::cout << "[LiveCapture] Started live packet capture on: " << resolved_device_ << std::endl;
    return true;
}

void LiveCaptureSource::close() {
    running_ = false;
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void LiveCaptureSource::stopCapture() {
    running_ = false;
    if (handle_ && pcap_breakloop) {
        pcap_breakloop(handle_);
    }
}

bool LiveCaptureSource::getNextPacket(RawPacket& packet) {
    if (!handle_ || !running_) {
        return false;
    }

    struct pcap_pkthdr* hdr = nullptr;
    const unsigned char* pkt_data = nullptr;

    int res = pcap_next_ex(handle_, &hdr, &pkt_data);
    if (res == 1) { // Packet read successfully
        if (!hdr || !pkt_data || hdr->caplen == 0) {
            packet.header.incl_len = 0;
            packet.header.orig_len = 0;
            return true;
        }

        packet.header.ts_sec  = static_cast<uint32_t>(hdr->ts.tv_sec);
        packet.header.ts_usec = static_cast<uint32_t>(hdr->ts.tv_usec);
        packet.header.incl_len = hdr->caplen;
        packet.header.orig_len = hdr->len;

        packet.data.assign(pkt_data, pkt_data + hdr->caplen);
        return true;
    } else if (res == 0) {
        // Read timeout - return empty packet so capture thread can continue cleanly
        packet.header.incl_len = 0;
        packet.header.orig_len = 0;
        return true;
    } else {
        // Error or loop broken
        return false;
    }
}

uint64_t LiveCaptureSource::getCaptureDrops() const {
    if (!handle_ || !pcap_stats) return 0;
    struct pcap_stat ps;
    if (pcap_stats(handle_, &ps) == 0) {
        return ps.ps_drop;
    }
    return 0;
}

} // namespace PacketAnalyzer
