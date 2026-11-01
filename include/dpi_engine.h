#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "packet_parser.h"
#include "types.h"
#include "tcp_reassembler.h"

namespace DPI {

class DPIEngine {
public:
    DPIEngine() = default;

    // Stateless & stateful reassembling payload inspector
    AppClassification inspect(const PacketAnalyzer::ParsedPacket& pkt);

    TcpReassembler& getReassembler() { return tcp_reassembler_; }

private:
    TcpReassembler tcp_reassembler_;
};

} // namespace DPI

#endif // DPI_ENGINE_H
