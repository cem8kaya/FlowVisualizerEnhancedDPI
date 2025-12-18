#include "s1ap_asn1_wrapper.h"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace callflow {
namespace asn1 {

// ============================================================================
// PerDecoder Implementation
// ============================================================================

PerDecoder::PerDecoder(const uint8_t* data, size_t len)
    : data_(data), length_(len), bit_offset_(0) {}

bool PerDecoder::readBits(uint8_t num_bits, uint32_t& value) {
    if (num_bits == 0 || num_bits > 32) {
        return false;
    }

    value = 0;

    for (uint8_t i = 0; i < num_bits; ++i) {
        size_t byte_pos = bit_offset_ / 8;
        size_t bit_pos = 7 - (bit_offset_ % 8);

        if (byte_pos >= length_) {
            return false;
        }

        uint8_t bit = (data_[byte_pos] >> bit_pos) & 1;
        value = (value << 1) | bit;
        bit_offset_++;
    }

    return true;
}

bool PerDecoder::readOctet(uint8_t& value) {
    alignToByte();

    size_t byte_pos = bit_offset_ / 8;
    if (byte_pos >= length_) {
        return false;
    }

    value = data_[byte_pos];
    bit_offset_ += 8;
    return true;
}

bool PerDecoder::readOctets(uint8_t* dest, size_t num_octets) {
    alignToByte();

    size_t byte_pos = bit_offset_ / 8;
    if (byte_pos + num_octets > length_) {
        return false;
    }

    std::memcpy(dest, data_ + byte_pos, num_octets);
    bit_offset_ += num_octets * 8;
    return true;
}

void PerDecoder::alignToByte() {
    if (bit_offset_ % 8 != 0) {
        bit_offset_ = ((bit_offset_ / 8) + 1) * 8;
    }
}

bool PerDecoder::skipBits(size_t num_bits) {
    bit_offset_ += num_bits;
    return bit_offset_ <= length_ * 8;
}

bool PerDecoder::hasMore() const {
    return bit_offset_ < length_ * 8;
}

uint8_t PerDecoder::bitsNeeded(uint32_t range) {
    if (range == 0) return 0;

    uint8_t bits = 0;
    while (range > 0) {
        bits++;
        range >>= 1;
    }
    return bits;
}

std::optional<uint32_t> PerDecoder::decodeConstrainedWholeNumber(uint32_t min_val, uint32_t max_val) {
    if (max_val < min_val) {
        return std::nullopt;
    }

    uint32_t range = max_val - min_val;

    if (range == 0) {
        // Only one value possible
        return min_val;
    }

    uint8_t num_bits = bitsNeeded(range);
    uint32_t value;

    if (!readBits(num_bits, value)) {
        return std::nullopt;
    }

    return min_val + value;
}

std::optional<uint32_t> PerDecoder::decodeLength() {
    uint32_t first_bit;
    if (!readBits(1, first_bit)) {
        return std::nullopt;
    }

    if (first_bit == 0) {
        // Short form: 7 bits
        uint32_t length;
        if (!readBits(7, length)) {
            return std::nullopt;
        }
        return length;
    } else {
        // Long form: check second bit
        uint32_t second_bit;
        if (!readBits(1, second_bit)) {
            return std::nullopt;
        }

        if (second_bit == 0) {
            // 14-bit length
            uint32_t length;
            if (!readBits(14, length)) {
                return std::nullopt;
            }
            return length;
        } else {
            // Fragmented (not commonly used in S1AP)
            return std::nullopt;
        }
    }
}

std::optional<std::vector<uint8_t>> PerDecoder::decodeOctetString() {
    auto length_opt = decodeLength();
    if (!length_opt.has_value()) {
        return std::nullopt;
    }

    uint32_t length = length_opt.value();
    std::vector<uint8_t> result(length);

    if (!readOctets(result.data(), length)) {
        return std::nullopt;
    }

    return result;
}

std::optional<bool> PerDecoder::decodeBoolean() {
    uint32_t value;
    if (!readBits(1, value)) {
        return std::nullopt;
    }
    return value != 0;
}

std::optional<uint32_t> PerDecoder::decodeEnumerated(uint32_t num_values) {
    if (num_values == 0) {
        return std::nullopt;
    }

    return decodeConstrainedWholeNumber(0, num_values - 1);
}

// ============================================================================
// S1AP PDU Decoding
// ============================================================================

std::optional<S1apPdu> decodeS1apPdu(const uint8_t* data, size_t len) {
    if (!data || len < 2) {
        return std::nullopt;
    }

    PerDecoder decoder(data, len);
    S1apPdu pdu;

    // Decode choice (CHOICE: initiatingMessage, successfulOutcome, unsuccessfulOutcome)
    auto choice_opt = decoder.decodeEnumerated(3);
    if (!choice_opt.has_value()) {
        return std::nullopt;
    }
    pdu.choice = static_cast<uint8_t>(choice_opt.value());

    // Decode procedure code (constrained integer 0..255)
    auto proc_code_opt = decoder.decodeConstrainedWholeNumber(0, 255);
    if (!proc_code_opt.has_value()) {
        return std::nullopt;
    }
    pdu.procedure_code = static_cast<uint8_t>(proc_code_opt.value());

    // Decode criticality (ENUMERATED: reject(0), ignore(1), notify(2))
    auto crit_opt = decoder.decodeEnumerated(3);
    if (!crit_opt.has_value()) {
        return std::nullopt;
    }
    pdu.criticality = static_cast<uint8_t>(crit_opt.value());

    // Rest is the value (encoded as OCTET STRING or SEQUENCE)
    // We'll store remaining data for further processing
    size_t current_byte = decoder.getCurrentBytePosition();
    if (current_byte < len) {
        pdu.value.assign(data + current_byte, data + len);
    }

    return pdu;
}

std::vector<S1apIeTuple> extractS1apIes(const uint8_t* data, size_t len) {
    std::vector<S1apIeTuple> ies;

    if (!data || len == 0) {
        return ies;
    }

    PerDecoder decoder(data, len);

    // S1AP IEs are encoded as a SEQUENCE OF ProtocolIE-Field
    // First, decode the sequence length
    auto num_ies_opt = decoder.decodeLength();
    if (!num_ies_opt.has_value()) {
        return ies;
    }

    uint32_t num_ies = num_ies_opt.value();

    for (uint32_t i = 0; i < num_ies && decoder.hasMore(); ++i) {
        S1apIeTuple ie;

        // Decode IE ID (0..65535)
        auto id_opt = decoder.decodeConstrainedWholeNumber(0, 65535);
        if (!id_opt.has_value()) {
            break;
        }
        ie.id = id_opt.value();

        // Decode criticality
        auto crit_opt = decoder.decodeEnumerated(3);
        if (!crit_opt.has_value()) {
            break;
        }
        ie.criticality = static_cast<uint8_t>(crit_opt.value());

        // Decode IE value (OCTET STRING)
        auto value_opt = decoder.decodeOctetString();
        if (!value_opt.has_value()) {
            break;
        }
        ie.value = value_opt.value();

        ies.push_back(ie);
    }

    return ies;
}

// ============================================================================
// S1AP IE Decoders
// ============================================================================

std::optional<std::string> decodeImsi(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return std::nullopt;
    }

    std::ostringstream oss;

    // IMSI is TBCD-encoded (BCD with each byte containing two digits)
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];

        // Lower nibble (first digit)
        uint8_t digit1 = byte & 0x0F;
        if (digit1 <= 9) {
            oss << static_cast<char>('0' + digit1);
        } else if (digit1 == 0x0F) {
            // Filler, stop
            break;
        }

        // Upper nibble (second digit)
        uint8_t digit2 = (byte >> 4) & 0x0F;
        if (digit2 <= 9) {
            oss << static_cast<char>('0' + digit2);
        } else if (digit2 == 0x0F) {
            // Filler, stop
            break;
        }
    }

    std::string imsi = oss.str();
    return imsi.empty() ? std::nullopt : std::make_optional(imsi);
}

std::optional<uint32_t> decodeUeId(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return std::nullopt;
    }

    PerDecoder decoder(data, len);

    // UE IDs are constrained integers
    // ENB-UE-S1AP-ID: INTEGER (0..16777215) -- 24 bits
    // MME-UE-S1AP-ID: INTEGER (0..4294967295) -- 32 bits
    // Try to decode as unconstrained or large integer

    if (len <= 4) {
        uint32_t value = 0;
        for (size_t i = 0; i < len; ++i) {
            value = (value << 8) | data[i];
        }
        return value;
    }

    return std::nullopt;
}

std::optional<std::vector<uint8_t>> decodeNasPdu(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return std::nullopt;
    }

    // NAS-PDU is an OCTET STRING, typically the data IS the NAS message
    // In ASN.1 PER encoding, we may need to skip length encoding
    PerDecoder decoder(data, len);

    auto nas_opt = decoder.decodeOctetString();
    if (nas_opt.has_value()) {
        return nas_opt;
    }

    // If that fails, assume the entire buffer is the NAS-PDU
    std::vector<uint8_t> nas_pdu(data, data + len);
    return nas_pdu;
}

}  // namespace asn1
}  // namespace callflow
