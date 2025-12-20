#pragma once

#include <array>
#include <cstdint>
#include <map>     // Added for NasSecurityManager
#include <memory>  // Added for NasSecurityManager
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace callflow {

/**
 * NAS Security Algorithm Types
 */
enum class NasCipheringAlgorithm : uint8_t {
    NEA0 = 0,  // Null ciphering
    NEA1 = 1,  // SNOW 3G
    NEA2 = 2,  // AES-128-CTR
    NEA3 = 3   // ZUC
};

enum class NasIntegrityAlgorithm : uint8_t {
    NIA0 = 0,  // Null integrity
    NIA1 = 1,  // SNOW 3G
    NIA2 = 2,  // AES-128-CMAC
    NIA3 = 3   // ZUC
};

/**
 * NAS Security Direction
 */
enum class NasDirection : uint8_t { UPLINK = 0, DOWNLINK = 1 };

/**
 * NAS Security Context
 * Holds keys and counters for a specific UE
 */
class NasSecurityContext {
public:
    NasSecurityContext() = default;

    // Set keys directly (e.g. from config)
    void setKeys(const std::vector<uint8_t>& k_nas_enc, const std::vector<uint8_t>& k_nas_int);

    // Set algorithms
    void setAlgorithms(NasCipheringAlgorithm cipher_alg, NasIntegrityAlgorithm integrity_alg);

    // Update counters
    void setUplinkCount(uint32_t count);
    void setDownlinkCount(uint32_t count);

    // Getters
    uint32_t getUplinkCount() const { return ul_count_; }
    uint32_t getDownlinkCount() const { return dl_count_; }

    /**
     * Decrypt NAS payload
     * @param payload Encrypted payload
     * @param count NAS COUNT value (Sequence Number + Overflow)
     * @param direction Uplink or Downlink
     * @param bearer_id Bearer identity (typically 0 for NAS)
     * @return Decrypted payload
     */
    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& payload, uint32_t count, NasDirection direction,
        uint8_t bearer_id = 1);  // Bearer 1 for NAS (approx, strictly speaking it's not bearer)

    /**
     * Verify Integrity
     * @param payload Message payload (including header)
     * @param count NAS COUNT value
     * @param direction Uplink or Downlink
     * @param mac Received MAC to verify against
     * @return true if valid
     */
    bool verifyIntegrity(const std::vector<uint8_t>& payload, uint32_t count,
                         NasDirection direction, const std::array<uint8_t, 4>& mac);

    // Key derivation helper (static)
    // Simplified: Derive K_NAS_int and K_NAS_enc from K_AMF/K_ASME
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> deriveNasKeys(
        const std::vector<uint8_t>& k_master, NasCipheringAlgorithm enc_alg,
        NasIntegrityAlgorithm int_alg);

private:
    std::vector<uint8_t> k_nas_enc_;
    std::vector<uint8_t> k_nas_int_;

    NasCipheringAlgorithm cipher_alg_ = NasCipheringAlgorithm::NEA0;
    NasIntegrityAlgorithm integrity_alg_ = NasIntegrityAlgorithm::NIA0;

    uint32_t ul_count_ = 0;
    uint32_t dl_count_ = 0;

    mutable std::mutex mutex_;
};

/**
 * Manager for NAS Security Contexts
 */
class NasSecurityManager {
public:
    static NasSecurityManager& getInstance();

    void addContext(const std::string& imsi, std::shared_ptr<NasSecurityContext> context);
    std::shared_ptr<NasSecurityContext> getContext(const std::string& imsi);

private:
    NasSecurityManager() = default;
    std::map<std::string, std::shared_ptr<NasSecurityContext>> contexts_;
};

}  // namespace callflow
