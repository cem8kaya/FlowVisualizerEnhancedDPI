#include "pcap_ingest/pcap_reader.h"
#include "common/utils.h"

namespace callflow {

PcapReader::PcapReader()
    : pcap_handle_(nullptr),
      datalink_type_(-1),
      snaplen_(0),
      is_open_(false) {
    resetStats();
}

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open(const std::string& filename) {
    if (is_open_) {
        LOG_WARN("PcapReader already has an open file, closing it first");
        close();
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_offline(filename.c_str(), errbuf);

    if (!pcap_handle_) {
        LOG_ERROR("Failed to open PCAP file '" << filename << "': " << errbuf);
        return false;
    }

    filename_ = filename;
    datalink_type_ = pcap_datalink(pcap_handle_);
    snaplen_ = pcap_snapshot(pcap_handle_);
    is_open_ = true;

    LOG_INFO("Opened PCAP file: " << filename
             << " (datalink=" << datalink_type_
             << ", snaplen=" << snaplen_ << ")");

    resetStats();
    return true;
}

void PcapReader::close() {
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    is_open_ = false;

    if (!filename_.empty()) {
        LOG_INFO("Closed PCAP file: " << filename_
                 << " (processed " << stats_.packets_processed << " packets, "
                 << stats_.bytes_processed << " bytes)");
        filename_.clear();
    }
}

bool PcapReader::isOpen() const {
    return is_open_;
}

int PcapReader::getDatalinkType() const {
    return datalink_type_;
}

int PcapReader::getSnaplen() const {
    return snaplen_;
}

bool PcapReader::readNextPacket(struct pcap_pkthdr& header, const uint8_t*& data) {
    if (!is_open_ || !pcap_handle_) {
        LOG_ERROR("Attempting to read from closed PCAP file");
        return false;
    }

    int result = pcap_next_ex(pcap_handle_, &header, &data);

    if (result == 1) {
        // Packet read successfully
        stats_.packets_processed++;
        stats_.bytes_processed += header.caplen;

        // Update time range
        auto ts = std::chrono::system_clock::from_time_t(header.ts.tv_sec) +
                  std::chrono::microseconds(header.ts.tv_usec);
        if (stats_.packets_processed == 1) {
            stats_.start_time = ts;
        }
        stats_.end_time = ts;

        return true;
    } else if (result == -2) {
        // End of file
        LOG_DEBUG("Reached end of PCAP file: " << filename_);
        return false;
    } else {
        // Error
        LOG_ERROR("Error reading packet from PCAP: " << pcap_geterr(pcap_handle_));
        return false;
    }
}

size_t PcapReader::processPackets(PacketCallback callback, void* user_context) {
    if (!is_open_ || !pcap_handle_) {
        LOG_ERROR("Cannot process packets: PCAP file not open");
        return 0;
    }

    if (!callback) {
        LOG_ERROR("Cannot process packets: callback is null");
        return 0;
    }

    size_t count = 0;
    struct pcap_pkthdr header;
    const uint8_t* data;

    while (readNextPacket(header, data)) {
        callback(data, &header, user_context);
        count++;

        // Log progress for large files
        if (count % 100000 == 0) {
            LOG_INFO("Processed " << count << " packets...");
        }
    }

    LOG_INFO("Finished processing " << count << " packets from " << filename_);
    return count;
}

void PcapReader::resetStats() {
    stats_ = Stats{};
    stats_.start_time = std::chrono::system_clock::now();
    stats_.end_time = stats_.start_time;
}

}  // namespace callflow
