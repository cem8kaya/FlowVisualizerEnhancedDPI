#include "transport/sctp_parser.h"
#include "common/logger.h"
#include <cstring>
#include <arpa/inet.h>
#include <sstream>

namespace callflow {

// ============================================================================
// SCTP Payload Protocol ID utilities
// ============================================================================

std::string getSctpPpidName(uint32_t ppid) {
    switch (static_cast<SctpPayloadProtocolId>(ppid)) {
        case SctpPayloadProtocolId::RESERVED: return "RESERVED";
        case SctpPayloadProtocolId::IUA: return "IUA";
        case SctpPayloadProtocolId::M2UA: return "M2UA";
        case SctpPayloadProtocolId::M3UA: return "M3UA";
        case SctpPayloadProtocolId::SUA: return "SUA";
        case SctpPayloadProtocolId::M2PA: return "M2PA";
        case SctpPayloadProtocolId::V5UA: return "V5UA";
        case SctpPayloadProtocolId::H248: return "H248";
        case SctpPayloadProtocolId::BICC: return "BICC";
        case SctpPayloadProtocolId::TALI: return "TALI";
        case SctpPayloadProtocolId::DUA: return "DUA";
        case SctpPayloadProtocolId::ASAP: return "ASAP";
        case SctpPayloadProtocolId::ENRP: return "ENRP";
        case SctpPayloadProtocolId::H323: return "H323";
        case SctpPayloadProtocolId::QIPC: return "QIPC";
        case SctpPayloadProtocolId::SIMCO: return "SIMCO";
        case SctpPayloadProtocolId::DDP_SEG: return "DDP_SEG";
        case SctpPayloadProtocolId::DDP_STREAM: return "DDP_STREAM";
        case SctpPayloadProtocolId::S1AP: return "S1AP";
        case SctpPayloadProtocolId::RUA: return "RUA";
        case SctpPayloadProtocolId::HNBAP: return "HNBAP";
        case SctpPayloadProtocolId::FORCES_HP: return "FORCES_HP";
        case SctpPayloadProtocolId::FORCES_MP: return "FORCES_MP";
        case SctpPayloadProtocolId::FORCES_LP: return "FORCES_LP";
        case SctpPayloadProtocolId::SBC_AP: return "SBC_AP";
        case SctpPayloadProtocolId::X2AP: return "X2AP";
        case SctpPayloadProtocolId::SABP: return "SABP";
        case SctpPayloadProtocolId::DIAMETER: return "DIAMETER";
        case SctpPayloadProtocolId::NGAP: return "NGAP";
        case SctpPayloadProtocolId::XWAP: return "XWAP";
        default:
            if (ppid >= 0x80) {
                return "VENDOR_SPECIFIC";
            }
            return "UNKNOWN";
    }
}

// ============================================================================
// CRC32C for SCTP checksum (RFC 4960 Appendix B)
// ============================================================================

static const uint32_t crc32c_table[256] = {
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351
};

static uint32_t crc32c(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc = crc32c_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

// ============================================================================
// Structure Methods
// ============================================================================

nlohmann::json SctpCommonHeader::toJson() const {
    nlohmann::json j;
    j["source_port"] = source_port;
    j["dest_port"] = dest_port;
    j["verification_tag"] = verification_tag;
    j["checksum"] = checksum;
    return j;
}

nlohmann::json SctpDataChunk::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["flags"] = flags;
    j["length"] = length;
    j["tsn"] = tsn;
    j["stream_id"] = stream_id;
    j["stream_sequence"] = stream_sequence;
    j["payload_protocol"] = payload_protocol;
    j["payload_protocol_name"] = getSctpPpidName(payload_protocol);
    j["data_length"] = user_data.size();
    j["unordered"] = unordered();
    j["beginning"] = beginning();
    j["ending"] = ending();
    return j;
}

SctpDataFragment SctpDataChunk::toFragment() const {
    SctpDataFragment frag;
    frag.stream_id = stream_id;
    frag.tsn = tsn;
    frag.stream_sequence = stream_sequence;
    frag.payload_protocol = payload_protocol;
    frag.unordered = unordered();
    frag.beginning = beginning();
    frag.ending = ending();
    frag.data = user_data;
    return frag;
}

nlohmann::json SctpSackChunk::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["cumulative_tsn_ack"] = cumulative_tsn_ack;
    j["a_rwnd"] = a_rwnd;
    j["num_gap_ack_blocks"] = num_gap_ack_blocks;
    j["num_duplicate_tsns"] = num_duplicate_tsns;
    return j;
}

nlohmann::json SctpInitChunk::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["initiate_tag"] = initiate_tag;
    j["a_rwnd"] = a_rwnd;
    j["num_outbound_streams"] = num_outbound_streams;
    j["num_inbound_streams"] = num_inbound_streams;
    j["initial_tsn"] = initial_tsn;
    return j;
}

nlohmann::json SctpChunk::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["type_name"] = getTypeName();
    j["flags"] = flags;
    j["length"] = length;
    j["data_length"] = data.size();
    return j;
}

std::string SctpChunk::getTypeName() const {
    switch (static_cast<SctpChunkType>(type)) {
        case SctpChunkType::DATA: return "DATA";
        case SctpChunkType::INIT: return "INIT";
        case SctpChunkType::INIT_ACK: return "INIT-ACK";
        case SctpChunkType::SACK: return "SACK";
        case SctpChunkType::HEARTBEAT: return "HEARTBEAT";
        case SctpChunkType::HEARTBEAT_ACK: return "HEARTBEAT-ACK";
        case SctpChunkType::ABORT: return "ABORT";
        case SctpChunkType::SHUTDOWN: return "SHUTDOWN";
        case SctpChunkType::SHUTDOWN_ACK: return "SHUTDOWN-ACK";
        case SctpChunkType::ERROR: return "ERROR";
        case SctpChunkType::COOKIE_ECHO: return "COOKIE-ECHO";
        case SctpChunkType::COOKIE_ACK: return "COOKIE-ACK";
        case SctpChunkType::SHUTDOWN_COMPLETE: return "SHUTDOWN-COMPLETE";
        case SctpChunkType::FORWARD_TSN: return "FORWARD-TSN";
        default: return "Unknown-" + std::to_string(type);
    }
}

nlohmann::json SctpAssociation::toJson() const {
    nlohmann::json j;
    j["association_id"] = association_id;
    j["source_port"] = source_port;
    j["dest_port"] = dest_port;
    j["local_verification_tag"] = local_verification_tag;
    j["peer_verification_tag"] = peer_verification_tag;
    j["state"] = static_cast<int>(state);
    j["num_outbound_streams"] = num_outbound_streams;
    j["num_inbound_streams"] = num_inbound_streams;
    j["local_tsn"] = local_tsn;
    j["peer_tsn"] = peer_tsn;
    j["cumulative_tsn_ack"] = cumulative_tsn_ack;
    j["packets_sent"] = packets_sent;
    j["packets_received"] = packets_received;
    j["bytes_sent"] = bytes_sent;
    j["bytes_received"] = bytes_received;
    j["data_chunks_sent"] = data_chunks_sent;
    j["data_chunks_received"] = data_chunks_received;
    return j;
}

nlohmann::json SctpPacket::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();
    j["chunk_count"] = chunks.size();

    nlohmann::json chunks_json = nlohmann::json::array();
    for (const auto& chunk : chunks) {
        chunks_json.push_back(chunk.toJson());
    }
    j["chunks"] = chunks_json;

    if (!data_chunks.empty()) {
        nlohmann::json data_chunks_json = nlohmann::json::array();
        for (const auto& dc : data_chunks) {
            data_chunks_json.push_back(dc.toJson());
        }
        j["data_chunks"] = data_chunks_json;
    }

    if (init_chunk.has_value()) {
        j["init_chunk"] = init_chunk.value().toJson();
    }

    return j;
}

// ============================================================================
// SctpParser Methods
// ============================================================================

SctpParser::SctpParser()
    : total_packets_parsed_(0),
      total_bytes_parsed_(0),
      total_associations_(0),
      parse_errors_(0) {
}

bool SctpParser::isSctp(const uint8_t* data, size_t len) {
    if (!data || len < 12) {
        return false;  // SCTP common header is 12 bytes
    }

    // SCTP doesn't have a magic number, but we can do basic sanity checks
    // Check that ports are non-zero
    uint16_t src_port, dst_port;
    std::memcpy(&src_port, data, 2);
    std::memcpy(&dst_port, data + 2, 2);
    src_port = ntohs(src_port);
    dst_port = ntohs(dst_port);

    if (src_port == 0 || dst_port == 0) {
        return false;
    }

    // Verify checksum
    return verifyChecksum(data, len);
}

std::optional<SctpPacket> SctpParser::parse(const uint8_t* data, size_t len,
                                             const FiveTuple& five_tuple) {
    if (!isSctp(data, len)) {
        LOG_DEBUG("Not a valid SCTP packet");
        parse_errors_++;
        return std::nullopt;
    }

    // Parse common header
    auto header_opt = parseCommonHeader(data, len);
    if (!header_opt.has_value()) {
        LOG_ERROR("Failed to parse SCTP common header");
        parse_errors_++;
        return std::nullopt;
    }

    SctpPacket packet;
    packet.header = header_opt.value();

    // Parse chunks
    if (!parseChunks(data, len, 12, packet)) {
        LOG_ERROR("Failed to parse SCTP chunks");
        parse_errors_++;
        return std::nullopt;
    }

    // Update statistics
    total_packets_parsed_++;
    total_bytes_parsed_ += len;

    // Get or create association
    auto& assoc = getOrCreateAssociation(five_tuple, packet.header.verification_tag);
    assoc.packets_received++;
    assoc.bytes_received += len;

    // Process all chunks for state transitions
    for (const auto& chunk : packet.chunks) {
        auto chunk_type = static_cast<SctpChunkType>(chunk.type);

        switch (chunk_type) {
            case SctpChunkType::INIT:
                if (packet.init_chunk.has_value()) {
                    const auto& init = packet.init_chunk.value();
                    assoc.peer_verification_tag = init.initiate_tag;
                    assoc.num_inbound_streams = init.num_outbound_streams;
                    assoc.num_outbound_streams = init.num_inbound_streams;
                    assoc.peer_tsn = init.initial_tsn;
                    updateAssociationState(assoc, SctpChunkType::INIT);
                }
                break;
            case SctpChunkType::INIT_ACK:
                updateAssociationState(assoc, SctpChunkType::INIT_ACK);
                break;
            case SctpChunkType::COOKIE_ECHO:
                updateAssociationState(assoc, SctpChunkType::COOKIE_ECHO);
                break;
            case SctpChunkType::COOKIE_ACK:
                updateAssociationState(assoc, SctpChunkType::COOKIE_ACK);
                break;
            case SctpChunkType::SHUTDOWN:
                updateAssociationState(assoc, SctpChunkType::SHUTDOWN);
                break;
            case SctpChunkType::SHUTDOWN_ACK:
                updateAssociationState(assoc, SctpChunkType::SHUTDOWN_ACK);
                break;
            case SctpChunkType::SHUTDOWN_COMPLETE:
                updateAssociationState(assoc, SctpChunkType::SHUTDOWN_COMPLETE);
                break;
            case SctpChunkType::HEARTBEAT:
                LOG_DEBUG("SCTP Association " << assoc.association_id << " | HEARTBEAT chunk received");
                break;
            case SctpChunkType::HEARTBEAT_ACK:
                LOG_DEBUG("SCTP Association " << assoc.association_id << " | HEARTBEAT_ACK chunk received");
                break;
            case SctpChunkType::ABORT:
                LOG_WARN("SCTP Association " << assoc.association_id << " | ABORT chunk received - connection aborted");
                assoc.state = SctpAssociationState::CLOSED;
                break;
            default:
                break;
        }
    }

    // Process data chunks
    if (!packet.data_chunks.empty()) {
        assoc.data_chunks_received += packet.data_chunks.size();
        processDataChunks(assoc, packet.data_chunks);
    }

    // Process SACK chunks
    if (!packet.sack_chunks.empty()) {
        processSackChunks(assoc, packet.sack_chunks);
    }

    LOG_DEBUG("Parsed SCTP packet with " << packet.chunks.size() << " chunks");

    return packet;
}

void SctpParser::setMessageCallback(SctpMessageCallback callback) {
    message_callback_ = callback;
}

std::optional<SctpAssociation> SctpParser::getAssociation(uint32_t association_id) const {
    auto it = associations_.find(association_id);
    if (it == associations_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<uint32_t> SctpParser::getAssociationIds() const {
    std::vector<uint32_t> ids;
    ids.reserve(associations_.size());
    for (const auto& pair : associations_) {
        ids.push_back(pair.first);
    }
    return ids;
}

std::optional<SctpStreamReassembler> SctpParser::getReassembler(uint32_t association_id) const {
    auto it = reassemblers_.find(association_id);
    if (it == reassemblers_.end()) {
        return std::nullopt;
    }
    return it->second;
}

nlohmann::json SctpParser::getStatistics() const {
    nlohmann::json j;
    j["total_packets_parsed"] = total_packets_parsed_;
    j["total_bytes_parsed"] = total_bytes_parsed_;
    j["total_associations"] = total_associations_;
    j["parse_errors"] = parse_errors_;
    j["active_associations"] = associations_.size();

    nlohmann::json assocs_json = nlohmann::json::array();
    for (const auto& pair : associations_) {
        assocs_json.push_back(pair.second.toJson());
    }
    j["associations"] = assocs_json;

    return j;
}

void SctpParser::clear() {
    associations_.clear();
    reassemblers_.clear();
    total_packets_parsed_ = 0;
    total_bytes_parsed_ = 0;
    total_associations_ = 0;
    parse_errors_ = 0;
}

// ============================================================================
// Private Methods
// ============================================================================

std::optional<SctpCommonHeader> SctpParser::parseCommonHeader(const uint8_t* data, size_t len) {
    if (len < 12) {
        return std::nullopt;
    }

    SctpCommonHeader header;

    std::memcpy(&header.source_port, data, 2);
    header.source_port = ntohs(header.source_port);

    std::memcpy(&header.dest_port, data + 2, 2);
    header.dest_port = ntohs(header.dest_port);

    std::memcpy(&header.verification_tag, data + 4, 4);
    header.verification_tag = ntohl(header.verification_tag);

    std::memcpy(&header.checksum, data + 8, 4);
    header.checksum = ntohl(header.checksum);

    return header;
}

bool SctpParser::parseChunks(const uint8_t* data, size_t len, size_t offset,
                             SctpPacket& packet) {
    while (offset < len) {
        // Need at least 4 bytes for chunk header
        if (offset + 4 > len) {
            break;
        }

        uint8_t chunk_type = data[offset];
        uint8_t chunk_flags = data[offset + 1];
        uint16_t chunk_length;
        std::memcpy(&chunk_length, data + offset + 2, 2);
        chunk_length = ntohs(chunk_length);

        // Check if we have the full chunk
        if (offset + chunk_length > len) {
            LOG_DEBUG("Incomplete chunk at offset " << offset);
            break;
        }

        // Parse specific chunk types
        if (chunk_type == static_cast<uint8_t>(SctpChunkType::DATA)) {
            auto data_chunk_opt = parseDataChunk(data + offset, chunk_length);
            if (data_chunk_opt.has_value()) {
                packet.data_chunks.push_back(data_chunk_opt.value());
            }
        } else if (chunk_type == static_cast<uint8_t>(SctpChunkType::SACK)) {
            auto sack_chunk_opt = parseSackChunk(data + offset, chunk_length);
            if (sack_chunk_opt.has_value()) {
                packet.sack_chunks.push_back(sack_chunk_opt.value());
            }
        } else if (chunk_type == static_cast<uint8_t>(SctpChunkType::INIT)) {
            auto init_chunk_opt = parseInitChunk(data + offset, chunk_length);
            if (init_chunk_opt.has_value()) {
                packet.init_chunk = init_chunk_opt.value();
            }
        }

        // Add generic chunk
        SctpChunk chunk;
        chunk.type = chunk_type;
        chunk.flags = chunk_flags;
        chunk.length = chunk_length;
        if (chunk_length > 4) {
            chunk.data.resize(chunk_length - 4);
            std::memcpy(chunk.data.data(), data + offset + 4, chunk_length - 4);
        }
        packet.chunks.push_back(chunk);

        // Move to next chunk (aligned to 4-byte boundary)
        size_t padded_length = (chunk_length + 3) & ~3;
        offset += padded_length;
    }

    return true;
}

std::optional<SctpDataChunk> SctpParser::parseDataChunk(const uint8_t* data, size_t len) {
    if (len < 16) {
        return std::nullopt;  // Minimum DATA chunk size
    }

    SctpDataChunk chunk;
    chunk.type = data[0];
    chunk.flags = data[1];

    std::memcpy(&chunk.length, data + 2, 2);
    chunk.length = ntohs(chunk.length);

    std::memcpy(&chunk.tsn, data + 4, 4);
    chunk.tsn = ntohl(chunk.tsn);

    std::memcpy(&chunk.stream_id, data + 8, 2);
    chunk.stream_id = ntohs(chunk.stream_id);

    std::memcpy(&chunk.stream_sequence, data + 10, 2);
    chunk.stream_sequence = ntohs(chunk.stream_sequence);

    std::memcpy(&chunk.payload_protocol, data + 12, 4);
    chunk.payload_protocol = ntohl(chunk.payload_protocol);

    // Copy user data
    if (chunk.length > 16) {
        size_t data_len = chunk.length - 16;
        chunk.user_data.resize(data_len);
        std::memcpy(chunk.user_data.data(), data + 16, data_len);
    }

    return chunk;
}

std::optional<SctpSackChunk> SctpParser::parseSackChunk(const uint8_t* data, size_t len) {
    if (len < 16) {
        return std::nullopt;  // Minimum SACK chunk size
    }

    SctpSackChunk chunk;
    chunk.type = data[0];
    chunk.flags = data[1];

    std::memcpy(&chunk.length, data + 2, 2);
    chunk.length = ntohs(chunk.length);

    std::memcpy(&chunk.cumulative_tsn_ack, data + 4, 4);
    chunk.cumulative_tsn_ack = ntohl(chunk.cumulative_tsn_ack);

    std::memcpy(&chunk.a_rwnd, data + 8, 4);
    chunk.a_rwnd = ntohl(chunk.a_rwnd);

    std::memcpy(&chunk.num_gap_ack_blocks, data + 12, 2);
    chunk.num_gap_ack_blocks = ntohs(chunk.num_gap_ack_blocks);

    std::memcpy(&chunk.num_duplicate_tsns, data + 14, 2);
    chunk.num_duplicate_tsns = ntohs(chunk.num_duplicate_tsns);

    size_t offset = 16;

    // Parse gap ack blocks
    for (uint16_t i = 0; i < chunk.num_gap_ack_blocks; ++i) {
        if (offset + 4 > len) {
            break;
        }

        uint16_t start, end;
        std::memcpy(&start, data + offset, 2);
        std::memcpy(&end, data + offset + 2, 2);
        start = ntohs(start);
        end = ntohs(end);

        chunk.gap_ack_blocks.push_back({start, end});
        offset += 4;
    }

    // Parse duplicate TSNs
    for (uint16_t i = 0; i < chunk.num_duplicate_tsns; ++i) {
        if (offset + 4 > len) {
            break;
        }

        uint32_t dup_tsn;
        std::memcpy(&dup_tsn, data + offset, 4);
        dup_tsn = ntohl(dup_tsn);

        chunk.duplicate_tsns.push_back(dup_tsn);
        offset += 4;
    }

    return chunk;
}

std::optional<SctpInitChunk> SctpParser::parseInitChunk(const uint8_t* data, size_t len) {
    if (len < 20) {
        return std::nullopt;  // Minimum INIT chunk size
    }

    SctpInitChunk chunk;
    chunk.type = data[0];
    chunk.flags = data[1];

    std::memcpy(&chunk.length, data + 2, 2);
    chunk.length = ntohs(chunk.length);

    std::memcpy(&chunk.initiate_tag, data + 4, 4);
    chunk.initiate_tag = ntohl(chunk.initiate_tag);

    std::memcpy(&chunk.a_rwnd, data + 8, 4);
    chunk.a_rwnd = ntohl(chunk.a_rwnd);

    std::memcpy(&chunk.num_outbound_streams, data + 12, 2);
    chunk.num_outbound_streams = ntohs(chunk.num_outbound_streams);

    std::memcpy(&chunk.num_inbound_streams, data + 14, 2);
    chunk.num_inbound_streams = ntohs(chunk.num_inbound_streams);

    std::memcpy(&chunk.initial_tsn, data + 16, 4);
    chunk.initial_tsn = ntohl(chunk.initial_tsn);

    return chunk;
}

SctpAssociation& SctpParser::getOrCreateAssociation(const FiveTuple& five_tuple,
                                                    uint32_t verification_tag) {
    uint32_t assoc_id = calculateAssociationId(five_tuple);

    auto it = associations_.find(assoc_id);
    if (it == associations_.end()) {
        // Create new association
        SctpAssociation assoc;
        assoc.association_id = assoc_id;
        assoc.source_port = five_tuple.src_port;
        assoc.dest_port = five_tuple.dst_port;
        assoc.peer_verification_tag = verification_tag;

        auto result = associations_.emplace(assoc_id, assoc);
        reassemblers_.emplace(assoc_id, SctpStreamReassembler());

        total_associations_++;
        return result.first->second;
    }

    return it->second;
}

void SctpParser::updateAssociationState(SctpAssociation& assoc, SctpChunkType chunk_type) {
    auto old_state = assoc.state;

    switch (chunk_type) {
        case SctpChunkType::INIT:
            assoc.state = SctpAssociationState::COOKIE_WAIT;
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " state transition: CLOSED -> COOKIE_WAIT (INIT received)"
                     << " | vtag=0x" << std::hex << assoc.peer_verification_tag
                     << " streams=" << std::dec << assoc.num_outbound_streams
                     << "/" << assoc.num_inbound_streams);
            break;
        case SctpChunkType::INIT_ACK:
            assoc.state = SctpAssociationState::COOKIE_ECHOED;
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " state transition: COOKIE_WAIT -> COOKIE_ECHOED (INIT_ACK received)");
            break;
        case SctpChunkType::COOKIE_ECHO:
            if (old_state == SctpAssociationState::CLOSED) {
                assoc.state = SctpAssociationState::ESTABLISHED;
                LOG_INFO("SCTP Association " << assoc.association_id
                         << " state transition: CLOSED -> ESTABLISHED (COOKIE_ECHO received, server side)");
            }
            break;
        case SctpChunkType::COOKIE_ACK:
            assoc.state = SctpAssociationState::ESTABLISHED;
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " state transition: COOKIE_ECHOED -> ESTABLISHED (COOKIE_ACK received)"
                     << " | Ready for data transfer on " << assoc.num_outbound_streams << " streams");
            break;
        case SctpChunkType::SHUTDOWN:
            assoc.state = SctpAssociationState::SHUTDOWN_RECEIVED;
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " state transition: ESTABLISHED -> SHUTDOWN_RECEIVED (SHUTDOWN received)"
                     << " | Total data chunks: " << assoc.data_chunks_received);
            break;
        case SctpChunkType::SHUTDOWN_ACK:
            assoc.state = SctpAssociationState::SHUTDOWN_ACK_SENT;
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " state transition -> SHUTDOWN_ACK_SENT (SHUTDOWN_ACK received)");
            break;
        case SctpChunkType::SHUTDOWN_COMPLETE:
            assoc.state = SctpAssociationState::CLOSED;
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " state transition -> CLOSED (SHUTDOWN_COMPLETE received)"
                     << " | Lifetime stats: " << assoc.packets_received << " packets, "
                     << assoc.bytes_received << " bytes, "
                     << assoc.data_chunks_received << " data chunks");
            break;
        default:
            // For DATA, SACK, HEARTBEAT, etc. - no state change
            break;
    }
}

void SctpParser::processDataChunks(SctpAssociation& assoc,
                                   const std::vector<SctpDataChunk>& data_chunks) {
    auto it = reassemblers_.find(assoc.association_id);
    if (it == reassemblers_.end()) {
        return;
    }

    auto& reassembler = it->second;

    for (const auto& data_chunk : data_chunks) {
        auto fragment = data_chunk.toFragment();

        // Log fragment details
        LOG_DEBUG("SCTP Association " << assoc.association_id
                  << " | Stream " << fragment.stream_id
                  << " | TSN=" << fragment.tsn
                  << " SSN=" << fragment.stream_sequence
                  << " PPID=" << fragment.payload_protocol
                  << " (" << getSctpPpidName(fragment.payload_protocol) << ")"
                  << " | Flags: " << (fragment.beginning ? "B" : "-")
                  << (fragment.ending ? "E" : "-")
                  << (fragment.unordered ? "U" : "-")
                  << " | Data: " << fragment.data.size() << " bytes");

        auto msg_opt = reassembler.addFragment(fragment);

        if (msg_opt.has_value() && message_callback_) {
            const auto& msg = msg_opt.value();
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " | Stream " << msg.stream_id
                     << " | SSN=" << msg.stream_sequence
                     << " | Reassembled complete message"
                     << " | PPID=" << msg.payload_protocol
                     << " (" << getSctpPpidName(msg.payload_protocol) << ")"
                     << " | TSN range: " << msg.start_tsn << "-" << msg.end_tsn
                     << " | Fragments: " << msg.fragment_count
                     << " | Total size: " << msg.data.size() << " bytes");
            message_callback_(msg);
        }
    }

    // Check for additional complete messages
    while (reassembler.hasCompleteMessages()) {
        auto msg_opt = reassembler.getCompleteMessage();
        if (msg_opt.has_value() && message_callback_) {
            const auto& msg = msg_opt.value();
            LOG_INFO("SCTP Association " << assoc.association_id
                     << " | Retrieved buffered complete message"
                     << " | Stream " << msg.stream_id
                     << " | SSN=" << msg.stream_sequence);
            message_callback_(msg);
        }
    }
}

void SctpParser::processSackChunks(SctpAssociation& assoc,
                                   const std::vector<SctpSackChunk>& sack_chunks) {
    auto it = reassemblers_.find(assoc.association_id);
    if (it == reassemblers_.end()) {
        return;
    }

    auto& reassembler = it->second;

    for (const auto& sack : sack_chunks) {
        assoc.cumulative_tsn_ack = sack.cumulative_tsn_ack;

        // Handle gaps - these indicate packet loss
        for (const auto& gap : sack.gap_ack_blocks) {
            uint32_t gap_start = sack.cumulative_tsn_ack + gap.first;
            uint32_t gap_end = sack.cumulative_tsn_ack + gap.second;

            // Notify all streams about the gap
            auto stream_ids = reassembler.getStreamIds();
            for (uint16_t stream_id : stream_ids) {
                reassembler.handleGap(stream_id, gap_start, gap_end);
            }
        }
    }
}

uint32_t SctpParser::calculateAssociationId(const FiveTuple& five_tuple) {
    // Simple hash based on 5-tuple
    return five_tuple.hash();
}

bool SctpParser::verifyChecksum(const uint8_t* data, size_t len) {
    if (len < 12) {
        return false;
    }

    // Extract checksum from packet
    uint32_t packet_checksum;
    std::memcpy(&packet_checksum, data + 8, 4);
    packet_checksum = ntohl(packet_checksum);

    // Create a copy with checksum field set to 0
    std::vector<uint8_t> data_copy(data, data + len);
    std::memset(data_copy.data() + 8, 0, 4);

    // Calculate CRC32C
    uint32_t calculated_checksum = crc32c(data_copy.data(), len);

    return calculated_checksum == packet_checksum;
}

}  // namespace callflow
