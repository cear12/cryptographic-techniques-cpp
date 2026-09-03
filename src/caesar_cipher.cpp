#include "cryptotech/caesar_cipher.h"

namespace educational_crypto {

namespace {
char shiftChar(char c, int shift) {
    if (c < 'A' || c > 'Z') return c;
    int normalizedShift = ((shift % 26) + 26) % 26;
    return static_cast<char>('A' + (c - 'A' + normalizedShift) % 26);
}
}  // namespace

std::string CaesarCipher::encrypt(const std::string& plaintext, int shift) {
    std::string out = plaintext;
    for (char& c : out) c = shiftChar(c, shift);
    return out;
}

std::string CaesarCipher::decrypt(const std::string& ciphertext, int shift) {
    return encrypt(ciphertext, -shift);
}

}  // namespace educational_crypto
