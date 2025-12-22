#include "common/nas_security_context.h"

#include <iomanip>
#include <iostream>

#include "common/crypto_utils.h"
#include "common/logger.h"

namespace callflow {

void NasSecurityContext::setKeys(const std::vector<uint8_t>& k_nas_enc,
                                 const std::vector<uint8_t>& k_nas_int) {
    std::lock_guard<std::mutex> lock(mutex_);
    k_nas_enc_ = k_nas_enc;
    k_nas_int_ = k_nas_int;
}

void NasSecurityContext::setAlgorithms(NasCipheringAlgorithm cipher_alg,
                                       NasIntegrityAlgorithm integrity_alg) {
    std::lock_guard<std::mutex> lock(mutex_);
    cipher_alg_ = cipher_alg;
    integrity_alg_ = integrity_alg;
}

void NasSecurityContext::setUplinkCount(uint32_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    ul_count_ = count;
}

void NasSecurityContext::setDownlinkCount(uint32_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    dl_count_ = count;
}

std::vector<uint8_t> NasSecurityContext::decrypt(const std::vector<uint8_t>& payload,
                                                 uint32_t count, NasDirection direction,
                                                 uint8_t bearer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (payload.empty()) {
        return {};
    }

    if (cipher_alg_ == NasCipheringAlgorithm::NEA0) {
        return payload;  // Null ciphering
    }

    if (k_nas_enc_.empty()) {
        LOG_ERROR("Cannot decrypt: NAS Encryption Key is missing");
        return {};
    }

    uint8_t dir_bit = (direction == NasDirection::UPLINK) ? 0 : 1;

    if (cipher_alg_ == NasCipheringAlgorithm::NEA2) {
        // AES-128-CTR (128-NEA2)
        return CryptoUtils::aes128ctr(payload, k_nas_enc_, count, bearer_id, dir_bit);
    }

    // Placeholder for NEA1/NEA3
    LOG_WARN("Unsupported ciphering algorithm: " << static_cast<int>(cipher_alg_));
    return {};
}

bool NasSecurityContext::verifyIntegrity(const std::vector<uint8_t>& payload, uint32_t count,
                                         NasDirection direction,
                                         const std::array<uint8_t, 4>& mac) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (integrity_alg_ == NasIntegrityAlgorithm::NIA0) {
        return true;  // Null integrity always passes (conceptually, though usually mac is checked)
    }

    if (k_nas_int_.empty()) {
        LOG_ERROR("Cannot verify: NAS Integrity Key is missing");
        return false;
    }

    uint8_t dir_bit = (direction == NasDirection::UPLINK) ? 0 : 1;
    uint8_t bearer_id = 1;  // NAS bearer

    if (integrity_alg_ == NasIntegrityAlgorithm::NIA2) {
        // AES-128-CMAC (128-NIA2)
        auto calculated_mac =
            CryptoUtils::aes128cmac(payload, k_nas_int_, count, bearer_id, dir_bit);

        if (calculated_mac.size() < 4)
            return false;

        return (calculated_mac[0] == mac[0] && calculated_mac[1] == mac[1] &&
                calculated_mac[2] == mac[2] && calculated_mac[3] == mac[3]);
    }

    LOG_WARN("Unsupported integrity algorithm: " << static_cast<int>(integrity_alg_));
    return false;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> NasSecurityContext::deriveNasKeys(
    const std::vector<uint8_t>& k_master, NasCipheringAlgorithm enc_alg,
    NasIntegrityAlgorithm int_alg) {
    // Suppress unused parameter warnings - these will be used when full KDF is implemented
    (void)k_master;
    (void)enc_alg;
    (void)int_alg;

    // Simplified key derivation (KDF)
    // S = FC || P0 || L0 || P1 || L1
    // FC = 0x69
    // P0 = algorithm type distinguisher (1 for NAS-enc, 2 for NAS-int)
    // L0 = length of P0 (0x00 0x01)
    // P1 = algorithm identity
    // L1 = length of P1 (0x00 0x01)

    // For now, we will return empty placeholders as full KDF implementation
    // often relies on HMAC-SHA256 which we need to ensure CryptoUtils provides.
    // This is a placeholder for future extension if dynamic derivation is needed.
    return {{}, {}};
}

// ============================================================================
// NasSecurityManager Implementation
// ============================================================================

NasSecurityManager& NasSecurityManager::getInstance() {
    static NasSecurityManager instance;
    return instance;
}

void NasSecurityManager::addContext(const std::string& imsi,
                                    std::shared_ptr<NasSecurityContext> context) {
    contexts_[imsi] = context;
    LOG_INFO("Added NAS security context for IMSI: " << imsi);
}

std::shared_ptr<NasSecurityContext> NasSecurityManager::getContext(const std::string& imsi) {
    auto it = contexts_.find(imsi);
    if (it != contexts_.end()) {
        return it->second;
    }
    return nullptr;
}

}  // namespace callflow
