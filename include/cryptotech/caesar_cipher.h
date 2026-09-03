#pragma once

#include <string>

namespace educational_crypto {

// Caesar (shift) cipher. Only 25 possible keys -- trivially brute-forceable
// and included purely as the historical starting point for the demo, not as
// a real security primitive. Operates on uppercase A-Z; non-letters pass
// through unchanged.
class CaesarCipher {
public:
    static std::string Encrypt(const std::string& plaintext, int shift);
    static std::string Decrypt(const std::string& ciphertext, int shift);
};

}  // namespace educational_crypto
