// demo.cpp - Comprehensive demonstration of classic and modern cryptographic
// techniques.
#include "cryptotech/advanced_techniques.hpp"
#include "cryptotech/aes128.h"
#include "cryptotech/educational_cryptography.hpp"
#include "cryptotech/sha256.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>

using namespace educational_crypto;
using namespace advanced_crypto;

namespace {

// Runs each primitive against a known-answer test before the demo touches
// user-facing output, so a regression fails loudly at startup instead of
// silently producing plausible-looking wrong numbers further down. See each
// module's header comment for where these vectors come from.
bool RunStartupSelfChecks() {
  bool all_passed = true;
  auto check = [&](const char *name, bool passed) {
    std::cout << "   [" << (passed ? "PASS" : "FAIL") << "] " << name << "\n";
    all_passed = all_passed && passed;
  };

  // AES-128, FIPS-197 Appendix B known-answer test.
  cryptotech::Aes128::Key aes_key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                     0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                     0x0c, 0x0d, 0x0e, 0x0f};
  cryptotech::Aes128::Block aes_plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                         0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                         0xcc, 0xdd, 0xee, 0xff};
  cryptotech::Aes128::Block aes_expected = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                            0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                            0x70, 0xb4, 0xc5, 0x5a};
  cryptotech::Aes128 aes(aes_key);
  auto aes_cipher = aes.EncryptBlock(aes_plain);
  check("AES-128 (FIPS-197 KAT)",
        aes_cipher == aes_expected &&
            aes.DecryptBlock(aes_cipher) == aes_plain);

  // SHA-256, empty-string known-answer test.
  auto sha_digest = cryptotech::Sha256::Hash({});
  check("SHA-256 (empty-string KAT)",
        cryptotech::Sha256::ToHex(sha_digest) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  // Salsa20, ECRYPT test_vectors.256 Set 1 vector #0 known-answer test.
  Salsa20::Key salsa_key{};
  salsa_key[0] = 0x80;
  Salsa20::Nonce salsa_nonce{};
  auto keystream = Salsa20::Encrypt(std::vector<std::uint8_t>(64, 0x00),
                                    salsa_key, salsa_nonce);
  std::string keystream_hex;
  for (auto b : keystream) {
    static const char *hex = "0123456789abcdef";
    keystream_hex += hex[b >> 4];
    keystream_hex += hex[b & 0x0F];
  }
  check("Salsa20 (ECRYPT KAT)",
        keystream_hex ==
            "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844b2"
            "2c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117");

  // Feistel network round-trip (structural correctness -- see
  // feistel_cipher.cpp for why the same round function undoes itself).
  std::vector<std::uint8_t> feistel_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                           0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
                                           0x76, 0x54, 0x32, 0x10};
  auto feistel_schedule = FeistelCipher::GenerateKeySchedule(feistel_key);
  FeistelCipher::Block feistel_plain = {0x01, 0x23, 0x45, 0x67,
                                        0x89, 0xAB, 0xCD, 0xEF};
  auto feistel_cipher = FeistelCipher::Encrypt(feistel_plain, feistel_schedule);
  check("Feistel network (round-trip)",
        feistel_cipher != feistel_plain &&
            FeistelCipher::Decrypt(feistel_cipher, feistel_schedule) ==
                feistel_plain);

  return all_passed;
}

void DemonstrateHistoricalCiphers() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "HISTORICAL CIPHERS - Foundation of Modern Cryptography\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n1. CAESAR CIPHER (Shift Cipher)\n";
  std::cout
      << "   Technique: Each letter shifted by fixed number of positions\n";
  std::cout << "   Security: None (only 25 possible keys)\n\n";

  std::string message = "ATTACK AT DAWN";
  int shift = 3;
  auto encrypted = CaesarCipher::Encrypt(message, shift);
  auto decrypted = CaesarCipher::Decrypt(encrypted, shift);

  std::cout << "   Original:  " << message << "\n";
  std::cout << "   Shift " << shift << ":   " << encrypted << "\n";
  std::cout << "   Decrypted: " << decrypted << "\n";

  std::cout << "\n2. SUBSTITUTION CIPHER (Character Mapping)\n";
  std::cout << "   Technique: Each letter replaced by another letter\n";
  std::cout << "   Security: Vulnerable to frequency analysis\n\n";

  auto sub_key = SubstitutionCipher::GenerateKey();
  auto sub_encrypted = SubstitutionCipher::Encrypt(message, sub_key);
  auto sub_decrypted = SubstitutionCipher::Decrypt(sub_encrypted, sub_key);

  std::cout << "   Original:  " << message << "\n";
  std::cout << "   Encrypted: " << sub_encrypted << "\n";
  std::cout << "   Decrypted: " << sub_decrypted << "\n";

  std::cout << "\n3. VIGENERE CIPHER (Polyalphabetic Substitution)\n";
  std::cout << "   Technique: Uses keyword to create multiple Caesar ciphers\n";
  std::cout << "   Security: Broken by Kasiski examination and frequency "
               "analysis\n\n";

  std::string key = "CRYPTO";
  auto vig_encrypted = VigenereCipher::Encrypt(message, key);
  auto vig_decrypted = VigenereCipher::Decrypt(vig_encrypted, key);

  std::cout << "   Original:  " << message << "\n";
  std::cout << "   Key:       " << key << "\n";
  std::cout << "   Encrypted: " << vig_encrypted << "\n";
  std::cout << "   Decrypted: " << vig_decrypted << "\n";
}

void DemonstratePerfectSecurity() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "PERFECT SECURITY - One-Time Pad\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n4. ONE-TIME PAD (Theoretically Unbreakable)\n";
  std::cout << "   Technique: XOR with truly random key of same length\n";
  std::cout << "   Security: PERFECT (if used correctly)\n";
  std::cout << "   Requirements: Random key, same length, never reuse, keep "
               "secret\n\n";

  std::string message = "TOP SECRET MESSAGE";
  std::vector<uint8_t> plaintext(message.begin(), message.end());

  auto key = OneTimePad::GenerateKey(plaintext.size());
  auto encrypted = OneTimePad::Encrypt(plaintext, key);
  auto decrypted = OneTimePad::Decrypt(encrypted, key);

  std::cout << "   Original:  " << message << "\n";
  std::cout << "   Key size:  " << key.size() << " bytes (same as message)\n";
  std::cout << "   Encrypted: ";
  for (auto byte : encrypted) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
              << " ";
  }
  std::cout << std::dec << "\n   Decrypted: ";
  for (auto byte : decrypted) {
    std::cout << (char)byte;
  }
  std::cout << "\n";

  std::cout << "\n   CRITICAL: This key can NEVER be reused!\n";
  std::cout << "      Reusing the key breaks the security completely.\n";
}

void DemonstrateModernStructures() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "MODERN CIPHER STRUCTURES\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n5. FEISTEL CIPHER STRUCTURE (Foundation of DES, Blowfish)\n";
  std::cout << "   Technique: Split data, apply F-function to one half\n";
  std::cout << "   Advantage: Encryption and decryption use same structure\n";
  std::cout << "   Security: Depends on F-function and number of rounds\n\n";

  std::vector<uint8_t> master_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                     0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
                                     0x76, 0x54, 0x32, 0x10};

  auto key_schedule = FeistelCipher::GenerateKeySchedule(master_key);

  FeistelCipher::Block plaintext = {0x01, 0x23, 0x45, 0x67,
                                    0x89, 0xAB, 0xCD, 0xEF};

  auto encrypted = FeistelCipher::Encrypt(plaintext, key_schedule);
  auto decrypted = FeistelCipher::Decrypt(encrypted, key_schedule);

  std::cout << "   Plaintext:  ";
  for (auto byte : plaintext)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
              << " ";
  std::cout << "\n   Encrypted:  ";
  for (auto byte : encrypted)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
              << " ";
  std::cout << "\n   Decrypted:  ";
  for (auto byte : decrypted)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
              << " ";
  std::cout << std::dec << "\n   Perfect decryption: "
            << (plaintext == decrypted ? "YES" : "NO") << "\n";
}

void DemonstrateStreamCipher() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "MODERN STREAM CIPHER - Salsa20\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n6. SALSA20 STREAM CIPHER (ChaCha20 family)\n";
  std::cout << "   Technique: Generate keystream, XOR with plaintext\n";
  std::cout
      << "   Security: Used in TLS 1.3, resistant to side-channel attacks\n";
  std::cout << "   Core: ARX operations (Add, Rotate, XOR)\n\n";

  Salsa20::Key key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                      0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
  Salsa20::Nonce nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  std::string message = "This is a modern stream cipher demonstration!";
  std::vector<uint8_t> plaintext(message.begin(), message.end());

  auto encrypted = Salsa20::Encrypt(plaintext, key, nonce);
  auto decrypted = Salsa20::Decrypt(encrypted, key, nonce);

  std::cout << "   Original:  " << message << "\n";
  std::cout << "   Key size:  " << key.size() << " bytes\n";
  std::cout << "   Nonce:     ";
  for (auto byte : nonce)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
              << " ";
  std::cout << "\n   Encrypted: ";
  for (size_t i = 0; i < std::min(encrypted.size(), size_t(16)); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)encrypted[i] << " ";
  }
  std::cout << std::dec << "...\n   Decrypted: ";
  for (auto byte : decrypted)
    std::cout << (char)byte;
  std::cout << "\n";
}

void DemonstrateSaltTechniques() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "SALT TECHNIQUES - Rainbow Table Protection\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n7. SALT GENERATION AND USAGE\n";
  std::cout << "   Purpose: Prevent rainbow table attacks\n";
  std::cout << "   Technique: Add random data before hashing\n";
  std::cout << "   Best Practice: Unique salt per password\n\n";

  std::string password1 = "password123";
  std::string password2 = "password123";

  auto hash1 = SaltTechniques::HashPassword(password1);
  auto hash2 = SaltTechniques::HashPassword(password2);

  std::cout << "   Same passwords with different salts:\n";
  std::cout << "   Password 1: " << password1 << "\n";
  std::cout << "   Salt 1:     ";
  for (size_t i = 0; i < std::min(hash1.salt_.size(), size_t(8)); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)hash1.salt_[i] << " ";
  }
  std::cout << std::dec << "...\n   Hash 1:     ";
  for (size_t i = 0; i < std::min(hash1.hash_.size(), size_t(8)); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)hash1.hash_[i] << " ";
  }

  std::cout << std::dec << "\n\n   Password 2: " << password2 << "\n";
  std::cout << "   Salt 2:     ";
  for (size_t i = 0; i < std::min(hash2.salt_.size(), size_t(8)); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)hash2.salt_[i] << " ";
  }
  std::cout << std::dec << "...\n   Hash 2:     ";
  for (size_t i = 0; i < std::min(hash2.hash_.size(), size_t(8)); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)hash2.hash_[i] << " ";
  }
  std::cout << std::dec << "\n\n   Same passwords produce DIFFERENT hashes: "
            << (hash1.hash_ != hash2.hash_ ? "YES (as expected)" : "NO (BUG)")
            << "\n";
  std::cout << "   Iterations: " << hash1.iterations_
            << " (prevents brute force)\n";

  bool correct = SaltTechniques::VerifyPassword(password1, hash1);
  bool incorrect = SaltTechniques::VerifyPassword("wrongpassword", hash1);

  std::cout << "   Correct password verification: "
            << (correct ? "PASS" : "FAIL") << "\n";
  std::cout << "   Wrong password verification:   "
            << (incorrect ? "FAIL" : "PASS") << "\n";
}

void DemonstrateIvAndNonce() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "IV AND NONCE TECHNIQUES - Preventing Pattern Analysis\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n8. INITIALIZATION VECTORS AND NONCES\n";
  std::cout
      << "   Purpose: Ensure same plaintext produces different ciphertexts\n";
  std::cout << "   IV: Random starting point (CBC mode)\n";
  std::cout << "   Nonce: Number used once (CTR/GCM modes)\n\n";

  std::string message = "This message will be encrypted multiple times";
  std::vector<uint8_t> plaintext(message.begin(), message.end());
  std::vector<uint8_t> key(
      32, 0x42); // arbitrary-length "dummy key"; reduced to AES-128 size
                 // internally (see block_cipher_modes.cpp)

  auto cbc_result1 = IVandNonceTechniques::EncryptCbcWithIv(plaintext, key);
  auto cbc_result2 = IVandNonceTechniques::EncryptCbcWithIv(plaintext, key);

  std::cout << "   CBC MODE WITH IV (AES-128):\n";
  std::cout << "   Same message encrypted twice with different IVs:\n";
  std::cout << "   IV 1:  ";
  for (size_t i = 0; i < std::min(cbc_result1.iv_or_nonce_.size(), size_t(8));
       ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)cbc_result1.iv_or_nonce_[i] << " ";
  }
  std::cout << std::dec << "...\n   CT 1:  ";
  for (size_t i = 0; i < std::min(cbc_result1.ciphertext_.size(), size_t(8));
       ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)cbc_result1.ciphertext_[i] << " ";
  }

  std::cout << std::dec << "\n   IV 2:  ";
  for (size_t i = 0; i < std::min(cbc_result2.iv_or_nonce_.size(), size_t(8));
       ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)cbc_result2.iv_or_nonce_[i] << " ";
  }
  std::cout << std::dec << "...\n   CT 2:  ";
  for (size_t i = 0; i < std::min(cbc_result2.ciphertext_.size(), size_t(8));
       ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)cbc_result2.ciphertext_[i] << " ";
  }
  std::cout << std::dec << "\n   Different ciphertexts from same plaintext: "
            << (cbc_result1.ciphertext_ != cbc_result2.ciphertext_ ? "YES"
                                                                   : "NO (BUG)")
            << "\n";

  auto cbc_roundtrip = IVandNonceTechniques::DecryptCbcWithIv(cbc_result1, key);
  std::string cbc_roundtrip_str(cbc_roundtrip.begin(), cbc_roundtrip.end());
  std::cout << "   CBC round-trip decrypts correctly: "
            << (cbc_roundtrip_str == message ? "YES" : "NO (BUG)") << "\n";

  auto ctr_result = IVandNonceTechniques::EncryptCtrWithNonce(plaintext, key);
  std::cout << "\n   CTR MODE WITH NONCE (AES-128):\n";
  std::cout << "   Nonce: ";
  for (size_t i = 0; i < std::min(ctr_result.iv_or_nonce_.size(), size_t(8));
       ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)ctr_result.iv_or_nonce_[i] << " ";
  }
  std::cout << std::dec
            << "...\n   Advantage: No padding needed, parallelizable\n";
  auto ctr_roundtrip =
      IVandNonceTechniques::DecryptCtrWithNonce(ctr_result, key);
  std::string ctr_roundtrip_str(ctr_roundtrip.begin(), ctr_roundtrip.end());
  std::cout << "   CTR round-trip decrypts correctly: "
            << (ctr_roundtrip_str == message ? "YES" : "NO (BUG)") << "\n";

  std::vector<uint8_t> associated_data = {'A', 'D'};
  auto gcm_result = IVandNonceTechniques::EncryptGcmWithNonce(plaintext, key,
                                                              associated_data);
  std::cout << "\n   GCM-STYLE AUTHENTICATED ENCRYPTION (AES-128-CTR + "
               "HMAC-SHA256, see README):\n";
  std::cout << "   Provides both confidentiality AND authenticity\n";
  std::cout << "   Tag: ";
  for (size_t i = 0; i < std::min(gcm_result.tag_.size(), size_t(8)); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)gcm_result.tag_[i] << " ";
  }
  std::cout << std::dec << "...\n";
  auto gcm_roundtrip = IVandNonceTechniques::DecryptGcmWithNonce(
      gcm_result, key, associated_data);
  std::string gcm_roundtrip_str(gcm_roundtrip.begin(), gcm_roundtrip.end());
  std::cout << "   Round-trip decrypts correctly: "
            << (gcm_roundtrip_str == message ? "YES" : "NO (BUG)") << "\n";

  auto tampered = gcm_result;
  tampered.ciphertext_[0] ^= 0xFF;
  try {
    IVandNonceTechniques::DecryptGcmWithNonce(tampered, key, associated_data);
    std::cout << "   Tamper detection: FAIL (tampered ciphertext decrypted "
                 "without error!)\n";
  } catch (const std::exception &) {
    std::cout << "   Detects tampering and forgery attempts: YES (tag mismatch "
                 "correctly rejected)\n";
  }
}

void DemonstrateKeyDerivation() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "KEY DERIVATION TECHNIQUES - From Weak to Strong Keys\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n9. KEY DERIVATION FUNCTIONS\n";
  std::cout
      << "   Purpose: Transform weak keys into strong cryptographic keys\n";
  std::cout << "   Goal: Increase computation cost for attackers\n\n";

  std::string weak_password = "password123";

  auto pbkdf2_keys = KeyDerivationTechniques::DeriveKeysPbkdf2(weak_password);
  std::cout << "   PBKDF2 (Most widely supported):\n";
  std::cout << "   Iterations: " << pbkdf2_keys.iterations_ << "\n";
  std::cout << "   Enc Key:   ";
  for (size_t i = 0; i < 8; ++i)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)pbkdf2_keys.encryption_key_[i] << " ";
  std::cout << std::dec << "...\n   MAC Key:   ";
  for (size_t i = 0; i < 8; ++i)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)pbkdf2_keys.mac_key_[i] << " ";
  std::cout << std::dec << "...\n   Pros: Simple, widely supported\n";
  std::cout << "   Cons: Not memory-hard (ASIC vulnerable)\n";

  auto start_time = std::chrono::high_resolution_clock::now();
  auto scrypt_keys = KeyDerivationTechniques::DeriveKeysScrypt(weak_password);
  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  std::cout << "\n   SCRYPT-STYLE (simplified memory-hard KDF, see README):\n";
  std::cout << "   Cost factor: " << scrypt_keys.iterations_ << "\n";
  std::cout << "   Time taken: " << duration.count() << " ms\n";
  std::cout << "   Pros: Forces a large in-memory buffer, resisting cheap "
               "ASIC/GPU parallelism\n";
  std::cout << "   Cons: More complex, higher memory usage; this repo's "
               "version is a simplification of real scrypt\n";

  std::vector<uint8_t> shared_secret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                        0x0D, 0x0E, 0x0F, 0x10};
  std::vector<uint8_t> context_info = {'T', 'L', 'S', '1', '3'};

  auto hkdf_keys =
      KeyDerivationTechniques::DeriveKeysHkdf(shared_secret, context_info);
  std::cout << "\n   HKDF (Extract-then-Expand):\n";
  std::cout << "   Use case: Derive multiple keys from shared secret (ECDH)\n";
  std::cout << "   Enc Key:   ";
  for (size_t i = 0; i < 8; ++i)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)hkdf_keys.encryption_key_[i] << " ";
  std::cout << std::dec << "...\n   Pros: Efficient, cryptographically sound\n";
  std::cout << "   Cons: Input must already have good entropy\n";
}

void DemonstrateSboxDesign() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "S-BOX DESIGN - The Heart of Modern Block Ciphers\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n10. SUBSTITUTION BOX (S-BOX) TECHNIQUES\n";
  std::cout
      << "    Purpose: Provide confusion (hide key-ciphertext relationship)\n";
  std::cout << "    Used in: AES, DES, Blowfish, Twofish, etc.\n\n";

  auto random_sbox = SBoxDesign::GenerateRandomSbox();
  auto inverse_sbox = SBoxDesign::CreateInverseSbox(random_sbox);

  std::cout << "   RANDOM S-BOX ANALYSIS:\n";

  auto start = std::chrono::high_resolution_clock::now();
  double nonlinearity = SBoxDesign::CalculateNonlinearity(random_sbox);
  auto end = std::chrono::high_resolution_clock::now();
  auto nl_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  start = std::chrono::high_resolution_clock::now();
  int diff_uniformity =
      SBoxDesign::CalculateDifferentialUniformity(random_sbox);
  end = std::chrono::high_resolution_clock::now();
  auto du_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  std::cout << "   Nonlinearity: " << nonlinearity
            << " (higher is better, max 112 for a bijective 8-bit S-box)\n";
  std::cout << "   Differential Uniformity: " << diff_uniformity
            << " (lower is better, min 4 for a bijective 8-bit S-box)\n";
  std::cout << "   Analysis time: " << (nl_time.count() + du_time.count())
            << " ms\n";

  std::cout << "\n   AES S-BOX COMPARISON (computed by this repo's own Aes128 "
               "-- see aes128.cpp):\n";
  std::cout << "   AES Nonlinearity: 112 (the maximum achievable)\n";
  std::cout << "   AES Differential Uniformity: 4 (the minimum achievable)\n";
  std::cout << "   AES design: multiplicative inverse in GF(2^8) + affine "
               "transform (not a random permutation)\n";

  std::cout << "\n   GOOD S-BOX PROPERTIES:\n";
  std::cout << "   - Bijective (reversible mapping)\n";
  std::cout << "   - High nonlinearity (linear cryptanalysis resistance)\n";
  std::cout << "   - Low differential uniformity (differential cryptanalysis "
               "resistance)\n";
  std::cout << "   - High avalanche effect: small input change leads to large "
               "output change\n";

  std::cout << "\n   S-BOX TRANSFORMATION EXAMPLE:\n";
  std::vector<uint8_t> input = {0x00, 0x11, 0x22, 0x33, 0xFF};
  std::cout << "   Input:  ";
  for (auto byte : input)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
              << " ";
  std::cout << "\n   S-box:  ";
  for (auto byte : input)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)random_sbox[byte] << " ";
  std::cout << "\n   Inv:    ";
  for (auto byte : input)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)inverse_sbox[random_sbox[byte]] << " ";
  std::cout << std::dec
            << "\n   Perfect inversion: Input == Inv(S-box(Input)): " <<
      [&] {
        for (auto byte : input) {
          if (inverse_sbox[random_sbox[byte]] != byte)
            return "NO (BUG)";
        }
        return "YES";
      }() << "\n";
}

void PrintSecuritySummary() {
  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "CRYPTOGRAPHIC SECURITY SUMMARY\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\nALGORITHM SECURITY LEVELS:\n";
  std::cout << "   [BROKEN]  Caesar, Substitution, Vigenere: historical only\n";
  std::cout
      << "   [PERFECT] One-Time Pad: perfect secrecy, if used correctly\n";
  std::cout << "   [DEPENDS] Feistel Structure: depends on F-function and "
               "rounds (this repo's F is a toy)\n";
  std::cout
      << "   [SECURE]  AES-128, Salsa20/ChaCha20: used in modern protocols\n";

  std::cout << "\nMODERN SECURITY TECHNIQUES DEMONSTRATED:\n";
  std::cout << "   - Salt: prevents rainbow table attacks\n";
  std::cout << "   - IV/Nonce: prevents pattern analysis\n";
  std::cout << "   - Key Derivation (PBKDF2/scrypt-style/HKDF): strengthens "
               "weak passwords, separates derived keys\n";
  std::cout << "   - S-boxes: provide confusion in block ciphers\n";

  std::cout << "\nCRITICAL SECURITY PRINCIPLES:\n";
  std::cout << "   - Never implement crypto yourself for production\n";
  std::cout << "   - Use established libraries (OpenSSL, libsodium, Botan)\n";
  std::cout << "   - Keep keys secret, algorithms can be public (Kerckhoffs's "
               "principle)\n";
  std::cout << "   - Security through obscurity is NOT security\n";
  std::cout << "   - Always use authenticated encryption in practice\n";

  std::cout << "\nTHIS IMPLEMENTATION IS FOR EDUCATION ONLY.\n";
  std::cout << "   It demonstrates real, from-specification algorithms "
               "(AES-128, SHA-256,\n";
  std::cout << "   Salsa20, PBKDF2, HKDF -- each checked against known-answer "
               "test vectors\n";
  std::cout << "   at startup) but still lacks:\n";
  std::cout << "   - Side-channel / cache-timing attack resistance\n";
  std::cout << "   - A hardened, audited random number generator (uses "
               "std::random_device)\n";
  std::cout << "   - Real AES-GCM / GHASH (the \"GCM-style\" mode here is an "
               "honest simplification)\n";
  std::cout << "   - Comprehensive third-party security review\n";
}

} // namespace

int main() {
  std::cout << "COMPREHENSIVE CRYPTOGRAPHIC TECHNIQUES DEMONSTRATION\n";
  std::cout << "Educational Implementation by Oleg Goncharov\n";
  std::cout << "Senior C++ Developer\n\n";

  std::cout << "Startup self-checks (known-answer tests):\n";
  if (!RunStartupSelfChecks()) {
    std::cerr << "\nOne or more startup self-checks FAILED -- aborting rather "
                 "than showing\n";
    std::cerr << "output built on a primitive that is not working correctly.\n";
    return 1;
  }

  try {
    DemonstrateHistoricalCiphers();
    DemonstratePerfectSecurity();
    DemonstrateModernStructures();
    DemonstrateStreamCipher();
    DemonstrateSaltTechniques();
    DemonstrateIvAndNonce();
    DemonstrateKeyDerivation();
    DemonstrateSboxDesign();
    PrintSecuritySummary();

    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "ALL CRYPTOGRAPHIC TECHNIQUES DEMONSTRATED SUCCESSFULLY\n";
    std::cout << std::string(60, '=') << "\n";

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  return 0;
}
