#include "cryptotech/caesar_cipher.h"

namespace educational_crypto {

namespace {
char ShiftChar(char c, int shift) {
  if (c < 'A' || c > 'Z')
    return c;
  int normalized_shift = ((shift % 26) + 26) % 26;
  return static_cast<char>('A' + (c - 'A' + normalized_shift) % 26);
}
} // namespace

std::string CaesarCipher::Encrypt(const std::string &plaintext, int shift) {
  std::string out = plaintext;
  for (char &c : out)
    c = ShiftChar(c, shift);
  return out;
}

std::string CaesarCipher::Decrypt(const std::string &ciphertext, int shift) {
  return Encrypt(ciphertext, -shift);
}

} // namespace educational_crypto
