#include "cryptotech/vigenere_cipher.h"

#include <stdexcept>

namespace educational_crypto {

namespace {
std::string apply(const std::string& text, const std::string& key, int sign) {
    if (key.empty()) throw std::invalid_argument("VigenereCipher: key must not be empty");

    std::string out = text;
    std::size_t keyIndex = 0;
    for (char& c : out) {
        if (c < 'A' || c > 'Z') continue;
        int keyShift = key[keyIndex % key.size()] - 'A';
        int shifted = (c - 'A' + sign * keyShift) % 26;
        if (shifted < 0) shifted += 26;
        c = static_cast<char>('A' + shifted);
        ++keyIndex;
    }
    return out;
}
}  // namespace

std::string VigenereCipher::encrypt(const std::string& plaintext, const std::string& key) {
    return apply(plaintext, key, +1);
}

std::string VigenereCipher::decrypt(const std::string& ciphertext, const std::string& key) {
    return apply(ciphertext, key, -1);
}

}  // namespace educational_crypto
