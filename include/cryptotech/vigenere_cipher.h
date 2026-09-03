#pragma once

#include <string>

namespace educational_crypto {

// Vigenere cipher: a repeating keyword selects a different Caesar shift for
// each letter. Historically significant (unbroken for ~300 years) but
// vulnerable to Kasiski examination once the key length is guessed --
// included for the historical narrative, not as a real primitive.
class VigenereCipher {
public:
    static std::string encrypt(const std::string& plaintext, const std::string& key);
    static std::string decrypt(const std::string& ciphertext, const std::string& key);
};

}  // namespace educational_crypto
