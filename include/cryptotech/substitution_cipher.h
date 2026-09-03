#pragma once

#include <array>
#include <string>

namespace educational_crypto {

// Monoalphabetic substitution cipher: each of the 26 letters is mapped to a
// (randomly-permuted) replacement letter. 26! possible keys, but broken in
// practice by frequency analysis on any non-trivial amount of ciphertext --
// included for the historical narrative, not as a real primitive.
class SubstitutionCipher {
public:
  // key[i] is the ciphertext letter substituted for plaintext letter 'A'+i.
  using Key = std::array<char, 26>;

  static Key GenerateKey();
  static std::string Encrypt(const std::string &plaintext, const Key &key);
  static std::string Decrypt(const std::string &ciphertext, const Key &key);
};

} // namespace educational_crypto
