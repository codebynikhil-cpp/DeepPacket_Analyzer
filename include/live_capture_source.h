#ifndef LIVE_CAPTURE_SOURCE_H
#define LIVE_CAPTURE_SOURCE_H

#include "packet_source.h"
#include "pcap_wrapper.h"
#include <atomic>

namespace PacketAnalyzer {

class LiveCaptureSource : public PacketSource {
public:
    explicit LiveCaptureSource(const std::string& device_name_or_index);
    ~LiveCaptureSource() override;

    bool open() override;
    void close() override;
    bool getNextPacket(RawPacket& packet) override;

    std::string getSourceName() const override { return display_name_; }
    std::string getMode() const override { return "live"; }
    bool isLive() const override { return true; }
    uint64_t getCaptureDrops() const override;

    void stopCapture();

private:
    std::string input_spec_;
    std::string resolved_device_;
    std::string display_name_;
    pcap_t* handle_ = nullptr;
    std::atomic<bool> running_{false};
};

} // namespace PacketAnalyzer

#endif // LIVE_CAPTURE_SOURCE_H
