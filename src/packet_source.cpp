#include "packet_source.h"
#include "pcap_wrapper.h"
#include <iostream>

#ifndef HAVE_NATIVE_PCAP_H
PcapLoader::fn_pcap_findalldevs PcapLoader::p_findalldevs = nullptr;
PcapLoader::fn_pcap_freealldevs PcapLoader::p_freealldevs = nullptr;
PcapLoader::fn_pcap_open_live   PcapLoader::p_open_live   = nullptr;
PcapLoader::fn_pcap_close       PcapLoader::p_close       = nullptr;
PcapLoader::fn_pcap_next_ex     PcapLoader::p_next_ex     = nullptr;
PcapLoader::fn_pcap_breakloop   PcapLoader::p_breakloop   = nullptr;
PcapLoader::fn_pcap_stats       PcapLoader::p_stats       = nullptr;
PcapLoader::fn_pcap_datalink    PcapLoader::p_datalink    = nullptr;
#endif

namespace PacketAnalyzer {

std::vector<InterfaceInfo> PacketSource::listInterfaces() {
    std::vector<InterfaceInfo> list;

#ifndef HAVE_NATIVE_PCAP_H
    if (!PcapLoader::init()) {
        std::cerr << "[PacketSource] Warning: Npcap / libpcap library not found on system." << std::endl;
        std::cerr << "               Live capture requires Npcap (Windows) or libpcap-dev (Linux/macOS)." << std::endl;
        return list;
    }
#endif

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        std::cerr << "[PacketSource] Error finding network devices: " << errbuf << std::endl;
        return list;
    }

    int idx = 1;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        InterfaceInfo info;
        info.index = idx++;
        info.name = d->name ? d->name : "";
        info.description = d->description ? d->description : "No description available";
        list.push_back(info);
    }

    pcap_freealldevs(alldevs);
    return list;
}

} // namespace PacketAnalyzer
