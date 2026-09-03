#pragma once

#include <cstdint>
#include <vector>

namespace cryptotech {

// Result of an encryption call: the random IV/nonce the caller must keep
// alongside the ciphertext to decrypt it, and (for the authenticated mode)
// a MAC tag.
struct CipherResult {
  std::vector<std::uint8_t> iv_or_nonce_;
  std::vector<std::uint8_t> ciphertext_;
  std::vector<std::uint8_t> tag_; // only populated by encryptGcmStyle()
};

// Demonstrates three classic block-cipher modes of operation, all built on
// the AES-128 primitive in aes128.h. The arbitrary-length "key" the demo
// passes in is reduced to an AES-128 key via SHA-256 (see keyFor()) so the
// same convenience API works regardless of how many bytes the caller hands
// in -- a common and legitimate pattern (HKDF/KDFs do the same thing more
// rigorously; see key_derivation.h).
//
// IMPORTANT -- "GCM-style": real AES-GCM authenticates ciphertext with
// GHASH, a GF(2^128) polynomial MAC, which is *not* implemented here. What
// IS implemented is an Encrypt-then-MAC construction (AES-CTR, then
// HMAC-SHA256 over nonce || associated data || ciphertext) that achieves
// the same three properties the demo advertises -- confidentiality,
// integrity, and additional-authenticated-data support -- through a
// different, simpler, equally standard construction. It is NOT
// byte-compatible with real AES-GCM. Do not use this in place of a real
// AEAD library for anything that matters.
class BlockCipherModes {
public:
  static CipherResult
  EncryptCbcWithIv(const std::vector<std::uint8_t> &plaintext,
                   const std::vector<std::uint8_t> &key);
  static std::vector<std::uint8_t>
  DecryptCbcWithIv(const CipherResult &in,
                   const std::vector<std::uint8_t> &key);

  static CipherResult
  EncryptCtrWithNonce(const std::vector<std::uint8_t> &plaintext,
                      const std::vector<std::uint8_t> &key);
  static std::vector<std::uint8_t>
  DecryptCtrWithNonce(const CipherResult &in,
                      const std::vector<std::uint8_t> &key);

  static CipherResult
  EncryptGcmStyle(const std::vector<std::uint8_t> &plaintext,
                  const std::vector<std::uint8_t> &key,
                  const std::vector<std::uint8_t> &associated_data);
  // Returns std::nullopt-like behavior via empty vector + `ok` flag: throws
  // std::runtime_error if the authentication tag does not match, so a
  // tampered ciphertext can never be silently "decrypted" into garbage
  // plaintext.
  static std::vector<std::uint8_t>
  DecryptGcmStyle(const CipherResult &in, const std::vector<std::uint8_t> &key,
                  const std::vector<std::uint8_t> &associated_data);
};

} // namespace cryptotech
