#include "protocol_parsers/s1ap/s1ap_ie_parser.h"
#include "common/logger.h"
#include <cstring>
#include <stdexcept>

namespace callflow {
namespace s1ap {

// ============================================================================
// Public IE Parser Functions
// ============================================================================

std::optional<uint32_t> S1APIEParser::parseENB_UE_S1AP_ID(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    // eNB-UE-S1AP-ID is a constrained integer: 0..16777215 (24-bit)
    // In ASN.1 PER, this is encoded in 3 bytes
    const uint8_t* ptr = data;
    size_t remaining = len;

    auto value = decodeConstrainedInteger(ptr, remaining, 0, 16777215);
    return value;
}

std::optional<uint32_t> S1APIEParser::parseMME_UE_S1AP_ID(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    // MME-UE-S1AP-ID is a constrained integer: 0..4294967295 (32-bit)
    const uint8_t* ptr = data;
    size_t remaining = len;

    auto value = decodeConstrainedInteger(ptr, remaining, 0, 4294967295);
    return value;
}

std::optional<std::vector<uint8_t>> S1APIEParser::parseNAS_PDU(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    // NAS-PDU is an OCTET STRING
    const uint8_t* ptr = data;
    size_t remaining = len;

    return decodeOctetString(ptr, remaining);
}

std::optional<TrackingAreaIdentity> S1APIEParser::parseTAI(const uint8_t* data, size_t len) {
    if (!data || len < 5) {
        return std::nullopt;
    }

    // TAI contains PLMN-Identity (3 bytes) + TAC (2 bytes)
    TrackingAreaIdentity tai;

    // Parse PLMN (3 bytes in BCD)
    tai.plmn_identity = decodePLMN(data);

    // Parse TAC (2 bytes, big-endian)
    tai.tac = (data[3] << 8) | data[4];

    return tai;
}

std::optional<EUTRAN_CGI> S1APIEParser::parseEUTRAN_CGI(const uint8_t* data, size_t len) {
    if (!data || len < 7) {
        return std::nullopt;
    }

    // E-UTRAN CGI contains PLMN-Identity (3 bytes) + Cell Identity (28 bits = 4 bytes)
    EUTRAN_CGI cgi;

    // Parse PLMN (3 bytes in BCD)
    cgi.plmn_identity = decodePLMN(data);

    // Parse Cell Identity (28 bits stored in 4 bytes)
    // The cell identity is typically left-aligned in the bit string
    cgi.cell_identity = ((data[3] << 24) | (data[4] << 16) | (data[5] << 8) | data[6]) >> 4;

    return cgi;
}

std::optional<UESecurityCapabilities> S1APIEParser::parseUESecurityCapabilities(const uint8_t* data, size_t len) {
    if (!data || len < 4) {
        return std::nullopt;
    }

    UESecurityCapabilities caps;

    // UE Security Capabilities contains two bit strings (16 bits each)
    // Encryption algorithms and integrity algorithms
    caps.encryption_algorithms = (data[0] << 8) | data[1];
    caps.integrity_algorithms = (data[2] << 8) | data[3];

    return caps;
}

std::optional<E_RAB_ToBeSetupItem> S1APIEParser::parseE_RAB_ToBeSetupItem(const uint8_t* data, size_t len) {
    if (!data || len < 10) {
        return std::nullopt;
    }

    // Simplified parsing - real ASN.1 parsing would be more complex
    E_RAB_ToBeSetupItem item;

    const uint8_t* ptr = data;
    size_t remaining = len;

    // Skip SEQUENCE header (simplified)
    ptr += 2;
    remaining -= 2;

    // Parse E-RAB-ID (constrained integer 0..15, 1 byte)
    if (remaining < 1) return std::nullopt;
    item.e_rab_id = ptr[0] & 0x0F;
    ptr++;
    remaining--;

    // Parse QoS parameters (simplified)
    auto qos = parseE_RAB_LevelQoSParameters(ptr, remaining);
    if (!qos.has_value()) {
        return std::nullopt;
    }
    item.qos_parameters = qos.value();

    // Skip to transport layer address (simplified navigation)
    // In real implementation, we'd properly decode the SEQUENCE structure
    ptr += 10;  // Approximate offset to transport layer address
    remaining -= 10;

    if (remaining < 4) return std::nullopt;

    // Parse Transport Layer Address (usually IPv4, 4 bytes)
    item.transport_layer_address = std::vector<uint8_t>(ptr, ptr + 4);
    ptr += 4;
    remaining -= 4;

    // Parse GTP-TEID (32-bit)
    if (remaining < 4) return std::nullopt;
    item.gtp_teid = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];

    return item;
}

std::optional<E_RAB_SetupItem> S1APIEParser::parseE_RAB_SetupItem(const uint8_t* data, size_t len) {
    if (!data || len < 9) {
        return std::nullopt;
    }

    E_RAB_SetupItem item;

    const uint8_t* ptr = data;
    size_t remaining = len;

    // Skip SEQUENCE header
    ptr += 2;
    remaining -= 2;

    // Parse E-RAB-ID
    if (remaining < 1) return std::nullopt;
    item.e_rab_id = ptr[0] & 0x0F;
    ptr++;
    remaining--;

    // Skip to transport layer address
    ptr += 2;
    remaining -= 2;

    // Parse Transport Layer Address
    if (remaining < 4) return std::nullopt;
    item.transport_layer_address = std::vector<uint8_t>(ptr, ptr + 4);
    ptr += 4;
    remaining -= 4;

    // Parse GTP-TEID
    if (remaining < 4) return std::nullopt;
    item.gtp_teid = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];

    return item;
}

std::optional<E_RAB_Item> S1APIEParser::parseE_RAB_Item(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    E_RAB_Item item;

    const uint8_t* ptr = data;
    size_t remaining = len;

    // Parse E-RAB-ID
    if (remaining < 1) return std::nullopt;
    item.e_rab_id = ptr[0] & 0x0F;

    return item;
}

std::optional<std::pair<S1APCauseType, uint8_t>> S1APIEParser::parseCause(const uint8_t* data, size_t len) {
    if (!data || len < 2) {
        return std::nullopt;
    }

    // Cause is a CHOICE with type and value
    S1APCauseType cause_type = static_cast<S1APCauseType>(data[0] & 0x07);
    uint8_t cause_value = data[1];

    return std::make_pair(cause_type, cause_value);
}

std::optional<uint8_t> S1APIEParser::parseRRCEstablishmentCause(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    // RRC Establishment Cause is an enumerated value (0..7)
    const uint8_t* ptr = data;
    size_t remaining = len;

    return decodeEnumerated(ptr, remaining, 7);
}

std::optional<E_RAB_LevelQoSParameters> S1APIEParser::parseE_RAB_LevelQoSParameters(const uint8_t* data, size_t len) {
    if (!data || len < 5) {
        return std::nullopt;
    }

    E_RAB_LevelQoSParameters qos;

    const uint8_t* ptr = data;

    // Parse QCI (constrained integer 0..255)
    qos.qci = ptr[0];
    ptr++;

    // Parse ARP (Allocation Retention Priority)
    qos.arp.priority_level = ptr[0] & 0x0F;
    qos.arp.pre_emption_capability = (ptr[1] & 0x01) != 0;
    qos.arp.pre_emption_vulnerability = (ptr[1] & 0x02) != 0;

    // GBR QoS is optional - not parsed in this simplified version

    return qos;
}

std::optional<std::vector<uint8_t>> S1APIEParser::parseTransportLayerAddress(const uint8_t* data, size_t len) {
    if (!data || len < 4) {
        return std::nullopt;
    }

    // Transport Layer Address is a BIT STRING
    // Usually contains IPv4 (32 bits = 4 bytes) or IPv6 (128 bits = 16 bytes)
    const uint8_t* ptr = data;
    size_t remaining = len;

    size_t bits_count = 0;
    return decodeBitString(ptr, remaining, bits_count);
}

std::optional<uint32_t> S1APIEParser::parseGTP_TEID(const uint8_t* data, size_t len) {
    if (!data || len < 4) {
        return std::nullopt;
    }

    // GTP-TEID is an OCTET STRING (SIZE (4))
    uint32_t teid = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    return teid;
}

// ============================================================================
// Private ASN.1 PER Helper Functions
// ============================================================================

std::string S1APIEParser::decodePLMN(const uint8_t* data) {
    // PLMN encoding (3GPP TS 24.008):
    // 3 bytes in BCD (Binary Coded Decimal)
    //
    // Byte 1: MCC digit 2 | MCC digit 1
    // Byte 2: MNC digit 3 | MCC digit 3
    // Byte 3: MNC digit 2 | MNC digit 1
    //
    // If MNC is 2 digits, MNC digit 3 is set to 0xF

    char plmn[8];
    uint8_t mcc1 = data[0] & 0x0F;
    uint8_t mcc2 = (data[0] >> 4) & 0x0F;
    uint8_t mcc3 = data[1] & 0x0F;
    uint8_t mnc3 = (data[1] >> 4) & 0x0F;
    uint8_t mnc1 = data[2] & 0x0F;
    uint8_t mnc2 = (data[2] >> 4) & 0x0F;

    if (mnc3 == 0x0F) {
        // 2-digit MNC
        snprintf(plmn, sizeof(plmn), "%01X%01X%01X%01X%01X",
                 mcc1, mcc2, mcc3, mnc1, mnc2);
    } else {
        // 3-digit MNC
        snprintf(plmn, sizeof(plmn), "%01X%01X%01X%01X%01X%01X",
                 mcc1, mcc2, mcc3, mnc1, mnc2, mnc3);
    }

    return std::string(plmn);
}

std::optional<size_t> S1APIEParser::decodeLength(const uint8_t*& ptr, size_t& remaining) {
    if (remaining < 1) {
        return std::nullopt;
    }

    size_t length = 0;

    if (ptr[0] & 0x80) {
        // Long form
        size_t num_octets = ptr[0] & 0x7F;
        ptr++;
        remaining--;

        if (num_octets > remaining || num_octets > 4) {
            return std::nullopt;
        }

        for (size_t i = 0; i < num_octets; i++) {
            length = (length << 8) | ptr[0];
            ptr++;
            remaining--;
        }
    } else {
        // Short form
        length = ptr[0];
        ptr++;
        remaining--;
    }

    return length;
}

std::optional<uint32_t> S1APIEParser::decodeConstrainedInteger(const uint8_t*& ptr, size_t& remaining,
                                                                uint32_t min, uint32_t max) {
    if (min == max) {
        // No encoding needed, value is constant
        return min;
    }

    // Calculate number of bits needed
    uint32_t range = max - min;
    size_t bits_needed = 0;
    uint32_t temp_range = range;
    while (temp_range > 0) {
        bits_needed++;
        temp_range >>= 1;
    }

    // Calculate number of bytes needed
    size_t bytes_needed = (bits_needed + 7) / 8;

    if (remaining < bytes_needed) {
        return std::nullopt;
    }

    uint32_t value = 0;
    for (size_t i = 0; i < bytes_needed; i++) {
        value = (value << 8) | ptr[0];
        ptr++;
        remaining--;
    }

    // Adjust for bit alignment
    size_t shift = (bytes_needed * 8) - bits_needed;
    value >>= shift;

    return min + value;
}

std::optional<uint32_t> S1APIEParser::decodeUnconstrainedInteger(const uint8_t*& ptr, size_t& remaining) {
    // Decode length first
    auto length = decodeLength(ptr, remaining);
    if (!length.has_value() || length.value() > 4 || length.value() > remaining) {
        return std::nullopt;
    }

    uint32_t value = 0;
    for (size_t i = 0; i < length.value(); i++) {
        value = (value << 8) | ptr[0];
        ptr++;
        remaining--;
    }

    return value;
}

std::optional<std::vector<uint8_t>> S1APIEParser::decodeOctetString(const uint8_t*& ptr, size_t& remaining) {
    // For S1AP, NAS-PDU is typically unconstrained
    // In simplified parsing, we just return the remaining data
    if (remaining == 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> result(ptr, ptr + remaining);
    ptr += remaining;
    remaining = 0;

    return result;
}

std::optional<std::vector<uint8_t>> S1APIEParser::decodeBitString(const uint8_t*& ptr, size_t& remaining,
                                                                   size_t& bits_count) {
    // Decode length (in bits)
    auto length = decodeLength(ptr, remaining);
    if (!length.has_value()) {
        return std::nullopt;
    }

    bits_count = length.value();
    size_t bytes_needed = (bits_count + 7) / 8;

    if (bytes_needed > remaining) {
        return std::nullopt;
    }

    std::vector<uint8_t> result(ptr, ptr + bytes_needed);
    ptr += bytes_needed;
    remaining -= bytes_needed;

    return result;
}

std::optional<uint8_t> S1APIEParser::decodeEnumerated(const uint8_t*& ptr, size_t& remaining,
                                                       uint8_t max_value) {
    // Enumerated is encoded like a constrained integer
    return static_cast<uint8_t>(decodeConstrainedInteger(ptr, remaining, 0, max_value).value_or(0));
}

bool S1APIEParser::skipIE(const uint8_t*& ptr, size_t& remaining) {
    auto length = decodeLength(ptr, remaining);
    if (!length.has_value() || length.value() > remaining) {
        return false;
    }

    ptr += length.value();
    remaining -= length.value();
    return true;
}

uint32_t S1APIEParser::readBits(const uint8_t*& ptr, size_t& bit_offset, size_t num_bits) {
    uint32_t result = 0;

    while (num_bits > 0) {
        size_t byte_offset = bit_offset / 8;
        size_t bit_in_byte = bit_offset % 8;
        size_t bits_available = 8 - bit_in_byte;
        size_t bits_to_read = (num_bits < bits_available) ? num_bits : bits_available;

        uint8_t mask = (1 << bits_to_read) - 1;
        uint8_t bits = (ptr[byte_offset] >> (bits_available - bits_to_read)) & mask;

        result = (result << bits_to_read) | bits;
        bit_offset += bits_to_read;
        num_bits -= bits_to_read;
    }

    return result;
}

} // namespace s1ap
} // namespace callflow
