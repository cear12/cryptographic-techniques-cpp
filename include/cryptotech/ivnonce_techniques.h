#pragma once

#include <cstdint>
#include <vector>

#include "cryptotech/block_cipher_modes.h"

namespace advanced_crypto {

// Thin snake_case-API wrapper over cryptotech::BlockCipherModes, so this
// namespace's demo-facing surface (IVandNonceTechniques::encrypt_cbc_with_iv,
// ...) reads consistently with the rest of the advanced_crypto classes.
// See block_cipher_modes.h for the actual mode implementations and, in
// particular, the "GCM-style" honesty note.
using EncryptionResult = cryptotech::CipherResult;

class IVandNonceTechniques {
public:
    static EncryptionResult encrypt_cbc_with_iv(const std::vector<std::uint8_t>& plaintext,
                                                 const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::encryptCbcWithIv(plaintext, key);
    }
    static std::vector<std::uint8_t> decrypt_cbc_with_iv(const EncryptionResult& in,
                                                           const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::decryptCbcWithIv(in, key);
    }

    static EncryptionResult encrypt_ctr_with_nonce(const std::vector<std::uint8_t>& plaintext,
                                                    const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::encryptCtrWithNonce(plaintext, key);
    }
    static std::vector<std::uint8_t> decrypt_ctr_with_nonce(const EncryptionResult& in,
                                                              const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::decryptCtrWithNonce(in, key);
    }

    static EncryptionResult encrypt_gcm_with_nonce(const std::vector<std::uint8_t>& plaintext,
                                                    const std::vector<std::uint8_t>& key,
                                                    const std::vector<std::uint8_t>& associated_data) {
        return cryptotech::BlockCipherModes::encryptGcmStyle(plaintext, key, associated_data);
    }
    static std::vector<std::uint8_t> decrypt_gcm_with_nonce(const EncryptionResult& in,
                                                              const std::vector<std::uint8_t>& key,
                                                              const std::vector<std::uint8_t>& associated_data) {
        return cryptotech::BlockCipherModes::decryptGcmStyle(in, key, associated_data);
    }
};

}  // namespace advanced_crypto
