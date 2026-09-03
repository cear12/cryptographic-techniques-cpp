#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace educational_crypto {

// Salsa20 stream cipher (Bernstein, 2005; the design ChaCha20 -- used in
// TLS 1.3 -- descends from). Generates a pseudorandom keystream from a
// 256-bit key and 64-bit nonce using only add/rotate/xor ("ARX") operations
// on a 4x4 matrix of 32-bit words, then XORs it with the input. Implemented
// directly from the public specification (20 rounds = 10 "double rounds"
// alternating column and row quarter-rounds). Encryption and decryption are
// the same XOR operation, so encrypt()/decrypt() are trivial wrappers
// around the same keystream generator.
class Salsa20 {
public:
  using Key = std::array<std::uint8_t, 32>;
  using Nonce = std::array<std::uint8_t, 8>;

  static std::vector<std::uint8_t>
  Encrypt(const std::vector<std::uint8_t> &plaintext, const Key &key,
          const Nonce &nonce);
  static std::vector<std::uint8_t>
  Decrypt(const std::vector<std::uint8_t> &ciphertext, const Key &key,
          const Nonce &nonce);
};

} // namespace educational_crypto
