#include "cryptotech/vigenere_cipher.h"

#include <stdexcept>

namespace educational_crypto {

namespace {
std::string Apply(const std::string& text, const std::string& key, int sign) {
    if (key.empty()) throw std::invalid_argument("VigenereCipher: key must not be empty");

    std::string out = text;
    std::size_t key_index = 0;
    for (char& c : out) {
        if (c < 'A' || c > 'Z') continue;
        int key_shift = key[key_index % key.size()] - 'A';
        int shifted = (c - 'A' + sign * key_shift) % 26;
        if (shifted < 0) shifted += 26;
        c = static_cast<char>('A' + shifted);
        ++key_index;
    }
    return out;
}
}  // namespace

std::string VigenereCipher::Encrypt(const std::string& plaintext, const std::string& key) {
    return Apply(plaintext, key, +1);
}

std::string VigenereCipher::Decrypt(const std::string& ciphertext, const std::string& key) {
    return Apply(ciphertext, key, -1);
}

}  // namespace educational_crypto
