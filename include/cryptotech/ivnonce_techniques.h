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
    static EncryptionResult EncryptCbcWithIv(const std::vector<std::uint8_t>& plaintext,
                                                 const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::EncryptCbcWithIv(plaintext, key);
    }
    static std::vector<std::uint8_t> DecryptCbcWithIv(const EncryptionResult& in,
                                                           const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::DecryptCbcWithIv(in, key);
    }

    static EncryptionResult EncryptCtrWithNonce(const std::vector<std::uint8_t>& plaintext,
                                                    const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::EncryptCtrWithNonce(plaintext, key);
    }
    static std::vector<std::uint8_t> DecryptCtrWithNonce(const EncryptionResult& in,
                                                              const std::vector<std::uint8_t>& key) {
        return cryptotech::BlockCipherModes::DecryptCtrWithNonce(in, key);
    }

    static EncryptionResult EncryptGcmWithNonce(const std::vector<std::uint8_t>& plaintext,
                                                    const std::vector<std::uint8_t>& key,
                                                    const std::vector<std::uint8_t>& associated_data) {
        return cryptotech::BlockCipherModes::EncryptGcmStyle(plaintext, key, associated_data);
    }
    static std::vector<std::uint8_t> DecryptGcmWithNonce(const EncryptionResult& in,
                                                              const std::vector<std::uint8_t>& key,
                                                              const std::vector<std::uint8_t>& associated_data) {
        return cryptotech::BlockCipherModes::DecryptGcmStyle(in, key, associated_data);
    }
};

}  // namespace advanced_crypto
