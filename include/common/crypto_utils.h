#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace callflow {

class CryptoUtils {
public:
    /**
     * AES-128-CTR Implementation (for 128-NEA2)
     * @param data Input data to decrypt/encrypt
     * @param key 128-bit key
     * @param count 32-bit count value
     * @param bearer 5-bit bearer ID
     * @param direction 1-bit direction (0=Uplink, 1=Downlink)
     * @return Decrypted/Encrypted data
     */
    static std::vector<uint8_t> aes128ctr(const std::vector<uint8_t>& data,
                                          const std::vector<uint8_t>& key, uint32_t count,
                                          uint8_t bearer, uint8_t direction);

    /**
     * AES-128-CMAC Implementation (for 128-NIA2)
     * Returns 4 bytes MAC (Truncated from 128-bit CMAC)
     */
    static std::vector<uint8_t> aes128cmac(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& key, uint32_t count,
                                           uint8_t bearer, uint8_t direction);

    /**
     * Generic HMAC-SHA256
     */
    static std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& data);
};

}  // namespace callflow
