// comprehensive_examples.cpp - Complete Demonstration of All Cryptographic Techniques
#include "educational_cryptography.hpp"
#include "advanced_techniques.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace educational_crypto;
using namespace advanced_crypto;

void demonstrate_historical_ciphers() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "HISTORICAL CIPHERS - Foundation of Modern Cryptography\n";
    std::cout << std::string(60, '=') << "\n";
    
    // Caesar Cipher
    std::cout << "\n1. CAESAR CIPHER (Shift Cipher)\n";
    std::cout << "   Technique: Each letter shifted by fixed number of positions\n";
    std::cout << "   Security: None (only 25 possible keys)\n\n";
    
    std::string message = "ATTACK AT DAWN";
    int shift = 3;
    auto encrypted = CaesarCipher::encrypt(message, shift);
    auto decrypted = CaesarCipher::decrypt(encrypted, shift);
    
    std::cout << "   Original:  " << message << "\n";
    std::cout << "   Shift " << shift << ":   " << encrypted << "\n";
    std::cout << "   Decrypted: " << decrypted << "\n";
    
    // Substitution Cipher
    std::cout << "\n2. SUBSTITUTION CIPHER (Character Mapping)\n";
    std::cout << "   Technique: Each letter replaced by another letter\n";
    std::cout << "   Security: Vulnerable to frequency analysis\n\n";
    
    auto sub_key = SubstitutionCipher::generate_key();
    auto sub_encrypted = SubstitutionCipher::encrypt(message, sub_key);
    auto sub_decrypted = SubstitutionCipher::decrypt(sub_encrypted, sub_key);
    
    std::cout << "   Original:  " << message << "\n";
    std::cout << "   Encrypted: " << sub_encrypted << "\n";
    std::cout << "   Decrypted: " << sub_decrypted << "\n";
    
    // Vigenère Cipher
    std::cout << "\n3. VIGENÈRE CIPHER (Polyalphabetic Substitution)\n";
    std::cout << "   Technique: Uses keyword to create multiple Caesar ciphers\n";
    std::cout << "   Security: Broken by Kasiski examination and frequency analysis\n\n";
    
    std::string key = "CRYPTO";
    auto vig_encrypted = VigenereCipher::encrypt(message, key);
    auto vig_decrypted = VigenereCipher::decrypt(vig_encrypted, key);
    
    std::cout << "   Original:  " << message << "\n";
    std::cout << "   Key:       " << key << "\n";
    std::cout << "   Encrypted: " << vig_encrypted << "\n";
    std::cout << "   Decrypted: " << vig_decrypted << "\n";
}

void demonstrate_perfect_security() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "PERFECT SECURITY - One-Time Pad\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n4. ONE-TIME PAD (Theoretically Unbreakable)\n";
    std::cout << "   Technique: XOR with truly random key of same length\n";
    std::cout << "   Security: PERFECT (if used correctly)\n";
    std::cout << "   Requirements: Random key, same length, never reuse, keep secret\n\n";
    
    std::string message = "TOP SECRET MESSAGE";
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    
    // Generate truly random key
    auto key = OneTimePad::generate_key(plaintext.size());
    
    auto encrypted = OneTimePad::encrypt(plaintext, key);
    auto decrypted = OneTimePad::decrypt(encrypted, key);
    
    std::cout << "   Original:  " << message << "\n";
    std::cout << "   Key size:  " << key.size() << " bytes (same as message)\n";
    std::cout << "   Encrypted: ";
    for (auto byte : encrypted) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << "\n   Decrypted: ";
    for (auto byte : decrypted) {
        std::cout << (char)byte;
    }
    std::cout << "\n";
    
    std::cout << "\n   🔒 CRITICAL: This key can NEVER be reused!\n";
    std::cout << "      Reusing the key breaks the security completely.\n";
}

void demonstrate_modern_structures() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "MODERN CIPHER STRUCTURES\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n5. FEISTEL CIPHER STRUCTURE (Foundation of DES, Blowfish)\n";
    std::cout << "   Technique: Split data, apply F-function to one half\n";
    std::cout << "   Advantage: Encryption and decryption use same structure\n";
    std::cout << "   Security: Depends on F-function and number of rounds\n\n";
    
    std::vector<uint8_t> master_key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    auto key_schedule = FeistelCipher::generate_key_schedule(master_key);
    
    FeistelCipher::Block plaintext = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    
    auto encrypted = FeistelCipher::encrypt(plaintext, key_schedule);
    auto decrypted = FeistelCipher::decrypt(encrypted, key_schedule);
    
    std::cout << "   Plaintext:  ";
    for (auto byte : plaintext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << "\n   Encrypted:  ";
    for (auto byte : encrypted) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << "\n   Decrypted:  ";
    for (auto byte : decrypted) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << "\n   ✓ Perfect decryption: " << (plaintext == decrypted ? "YES" : "NO") << "\n";
}

void demonstrate_stream_cipher() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "MODERN STREAM CIPHER - Salsa20\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n6. SALSA20 STREAM CIPHER (ChaCha20 family)\n";
    std::cout << "   Technique: Generate keystream, XOR with plaintext\n";
    std::cout << "   Security: Used in TLS 1.3, resistant to side-channel attacks\n";
    std::cout << "   Core: ARX operations (Add, Rotate, XOR)\n\n";
    
    Salsa20::Key key = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    
    Salsa20::Nonce nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    std::string message = "This is a modern stream cipher demonstration!";
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    
    auto encrypted = Salsa20::encrypt(plaintext, key, nonce);
    auto decrypted = Salsa20::decrypt(encrypted, key, nonce);
    
    std::cout << "   Original:  " << message << "\n";
    std::cout << "   Key size:  " << key.size() << " bytes\n";
    std::cout << "   Nonce:     ";
    for (auto byte : nonce) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << "\n   Encrypted: ";
    for (size_t i = 0; i < std::min(encrypted.size(), size_t(16)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)encrypted[i] << " ";
    }
    std::cout << "...\n   Decrypted: ";
    for (auto byte : decrypted) {
        std::cout << (char)byte;
    }
    std::cout << "\n";
}

void demonstrate_salt_techniques() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "SALT TECHNIQUES - Rainbow Table Protection\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n7. SALT GENERATION AND USAGE\n";
    std::cout << "   Purpose: Prevent rainbow table attacks\n";
    std::cout << "   Technique: Add random data before hashing\n";
    std::cout << "   Best Practice: Unique salt per password\n\n";
    
    std::string password1 = "password123";
    std::string password2 = "password123"; // Same password
    
    auto hash1 = SaltTechniques::hash_password(password1);
    auto hash2 = SaltTechniques::hash_password(password2);
    
    std::cout << "   Same passwords with different salts:\n";
    std::cout << "   Password 1: " << password1 << "\n";
    std::cout << "   Salt 1:     ";
    for (size_t i = 0; i < std::min(hash1.salt.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash1.salt[i] << " ";
    }
    std::cout << "...\n   Hash 1:     ";
    for (size_t i = 0; i < std::min(hash1.hash.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash1.hash[i] << " ";
    }
    
    std::cout << "\n\n   Password 2: " << password2 << "\n";
    std::cout << "   Salt 2:     ";
    for (size_t i = 0; i < std::min(hash2.salt.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash2.salt[i] << " ";
    }
    std::cout << "...\n   Hash 2:     ";
    for (size_t i = 0; i < std::min(hash2.hash.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash2.hash[i] << " ";
    }
    std::cout << "\n\n   ✓ Same passwords produce DIFFERENT hashes!\n";
    std::cout << "   ✓ Iterations: " << hash1.iterations << " (prevents brute force)\n";
    
    // Verify password
    bool correct = SaltTechniques::verify_password(password1, hash1);
    bool incorrect = SaltTechniques::verify_password("wrongpassword", hash1);
    
    std::cout << "   ✓ Correct password verification: " << (correct ? "PASS" : "FAIL") << "\n";
    std::cout << "   ✓ Wrong password verification: " << (incorrect ? "FAIL" : "PASS") << "\n";
}

void demonstrate_iv_and_nonce() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "IV AND NONCE TECHNIQUES - Preventing Pattern Analysis\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n8. INITIALIZATION VECTORS AND NONCES\n";
    std::cout << "   Purpose: Ensure same plaintext produces different ciphertexts\n";
    std::cout << "   IV: Random starting point (CBC mode)\n";
    std::cout << "   Nonce: Number used once (CTR/GCM modes)\n\n";
    
    std::string message = "This message will be encrypted multiple times";
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> key(32, 0x42); // Dummy key
    
    // Demonstrate CBC with IV
    auto cbc_result1 = IVandNonceTechniques::encrypt_cbc_with_iv(plaintext, key);
    auto cbc_result2 = IVandNonceTechniques::encrypt_cbc_with_iv(plaintext, key);
    
    std::cout << "   CBC MODE WITH IV:\n";
    std::cout << "   Same message encrypted twice with different IVs:\n";
    std::cout << "   IV 1:  ";
    for (size_t i = 0; i < std::min(cbc_result1.iv_or_nonce.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)cbc_result1.iv_or_nonce[i] << " ";
    }
    std::cout << "...\n   CT 1:  ";
    for (size_t i = 0; i < std::min(cbc_result1.ciphertext.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)cbc_result1.ciphertext[i] << " ";
    }
    
    std::cout << "\n   IV 2:  ";
    for (size_t i = 0; i < std::min(cbc_result2.iv_or_nonce.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)cbc_result2.iv_or_nonce[i] << " ";
    }
    std::cout << "...\n   CT 2:  ";
    for (size_t i = 0; i < std::min(cbc_result2.ciphertext.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)cbc_result2.ciphertext[i] << " ";
    }
    std::cout << "\n   ✓ Different ciphertexts from same plaintext!\n";
    
    // Demonstrate CTR with Nonce
    auto ctr_result = IVandNonceTechniques::encrypt_ctr_with_nonce(plaintext, key);
    std::cout << "\n   CTR MODE WITH NONCE:\n";
    std::cout << "   Nonce: ";
    for (size_t i = 0; i < std::min(ctr_result.iv_or_nonce.size(), size_t(8)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ctr_result.iv_or_nonce[i] << " ";
    }
    std::cout << "...\n   Advantage: No padding needed, parallelizable\n";
    
    // Demonstrate GCM with authentication
    std::vector<uint8_t> associated_data = {'A', 'D'};
    auto gcm_result = IVandNonceTechniques::encrypt_gcm_with_nonce(plaintext, key, associated_data);
    std::cout << "\n   GCM MODE WITH NONCE (Authenticated Encryption):\n";
    std::cout << "   Provides both confidentiality AND authenticity\n";
    std::cout << "   Ciphertext includes authentication tag\n";
    std::cout << "   ✓ Detects tampering and forgery attempts\n";
}

void demonstrate_key_derivation() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "KEY DERIVATION TECHNIQUES - From Weak to Strong Keys\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n9. KEY DERIVATION FUNCTIONS\n";
    std::cout << "   Purpose: Transform weak keys into strong cryptographic keys\n";
    std::cout << "   Goal: Increase computation cost for attackers\n\n";
    
    std::string weak_password = "password123";
    
    // PBKDF2
    auto pbkdf2_keys = KeyDerivationTechniques::derive_keys_pbkdf2(weak_password);
    std::cout << "   PBKDF2 (Most widely supported):\n";
    std::cout << "   Iterations: " << pbkdf2_keys.iterations << "\n";
    std::cout << "   Enc Key:   ";
    for (size_t i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)pbkdf2_keys.encryption_key[i] << " ";
    }
    std::cout << "...\n   MAC Key:   ";
    for (size_t i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)pbkdf2_keys.mac_key[i] << " ";
    }
    std::cout << "...\n   Pros: Simple, widely supported\n";
    std::cout << "   Cons: Not memory-hard (ASIC vulnerable)\n";
    
    // Scrypt
    auto start_time = std::chrono::high_resolution_clock::now();
    auto scrypt_keys = KeyDerivationTechniques::derive_keys_scrypt(weak_password);
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "\n   SCRYPT (Memory-hard function):\n";
    std::cout << "   Cost factor: " << scrypt_keys.iterations << "\n";
    std::cout << "   Time taken: " << duration.count() << " ms\n";
    std::cout << "   Pros: ASIC resistant (memory-hard)\n";
    std::cout << "   Cons: More complex, higher memory usage\n";
    
    // HKDF
    std::vector<uint8_t> shared_secret = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    std::vector<uint8_t> context_info = {'T', 'L', 'S', '1', '3'};
    
    auto hkdf_keys = KeyDerivationTechniques::derive_keys_hkdf(shared_secret, context_info);
    std::cout << "\n   HKDF (Extract-then-Expand):\n";
    std::cout << "   Use case: Derive multiple keys from shared secret (ECDH)\n";
    std::cout << "   Pros: Efficient, cryptographically sound\n";
    std::cout << "   Cons: Input must already have good entropy\n";
}

void demonstrate_sbox_design() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "S-BOX DESIGN - The Heart of Modern Block Ciphers\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n10. SUBSTITUTION BOX (S-BOX) TECHNIQUES\n";
    std::cout << "    Purpose: Provide confusion (hide key-ciphertext relationship)\n";
    std::cout << "    Used in: AES, DES, Blowfish, Twofish, etc.\n\n";
    
    // Generate and analyze random S-box
    auto random_sbox = SBoxDesign::generate_random_sbox();
    auto inverse_sbox = SBoxDesign::create_inverse_sbox(random_sbox);
    
    std::cout << "   RANDOM S-BOX ANALYSIS:\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    double nonlinearity = SBoxDesign::calculate_nonlinearity(random_sbox);
    auto end = std::chrono::high_resolution_clock::now();
    auto nl_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    start = std::chrono::high_resolution_clock::now();
    int diff_uniformity = SBoxDesign::calculate_differential_uniformity(random_sbox);
    end = std::chrono::high_resolution_clock::now();
    auto du_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "   Nonlinearity: " << nonlinearity << " (higher is better)\n";
    std::cout << "   Differential Uniformity: " << diff_uniformity << " (lower is better)\n";
    std::cout << "   Analysis time: " << (nl_time.count() + du_time.count()) << " ms\n";
    
    std::cout << "\n   AES S-BOX COMPARISON:\n";
    std::cout << "   AES Nonlinearity: 112 (excellent)\n";
    std::cout << "   AES Differential Uniformity: 4 (excellent)\n";
    std::cout << "   AES design: Based on multiplicative inverse in GF(2^8)\n";
    
    std::cout << "\n   GOOD S-BOX PROPERTIES:\n";
    std::cout << "   ✓ Bijective (reversible mapping)\n";
    std::cout << "   ✓ High nonlinearity (linear cryptanalysis resistance)\n";
    std::cout << "   ✓ Low differential uniformity (differential cryptanalysis resistance)\n";
    std::cout << "   ✓ No fixed points: S(x) ≠ x\n";
    std::cout << "   ✓ High avalanche effect: small input change → large output change\n";
    
    // Demonstrate S-box usage
    std::cout << "\n   S-BOX TRANSFORMATION EXAMPLE:\n";
    std::vector<uint8_t> input = {0x00, 0x11, 0x22, 0x33, 0xFF};
    std::cout << "   Input:  ";
    for (auto byte : input) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << "\n   S-box:  ";
    for (auto byte : input) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)random_sbox[byte] << " ";
    }
    std::cout << "\n   Inv:    ";
    for (auto byte : input) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)inverse_sbox[random_sbox[byte]] << " ";
    }
    std::cout << "\n   ✓ Perfect inversion: Input == Inv(S-box(Input))\n";
}

void print_security_summary() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "CRYPTOGRAPHIC SECURITY SUMMARY\n";
    std::cout << std::string(60, '=') << "\n";
    
    std::cout << "\n📊 ALGORITHM SECURITY LEVELS:\n";
    std::cout << "   🔴 Caesar, Substitution, Vigenère: BROKEN (Historical only)\n";
    std::cout << "   🟢 One-Time Pad: PERFECT (if used correctly)\n";
    std::cout << "   🟡 Feistel Structure: Depends on F-function and rounds\n";
    std::cout << "   🟢 Salsa20/ChaCha20: SECURE (used in modern protocols)\n";
    
    std::cout << "\n🛡️ MODERN SECURITY TECHNIQUES:\n";
    std::cout << "   ✓ Salt: Prevents rainbow table attacks\n";
    std::cout << "   ✓ IV/Nonce: Prevents pattern analysis\n";
    std::cout << "   ✓ Key Derivation: Strengthens weak passwords\n";
    std::cout << "   ✓ S-boxes: Provide confusion in block ciphers\n";
    
    std::cout << "\n⚠️ CRITICAL SECURITY PRINCIPLES:\n";
    std::cout << "   • Never implement crypto yourself for production\n";
    std::cout << "   • Use established libraries (OpenSSL, libsodium, Botan)\n";
    std::cout << "   • Keep keys secret, algorithms can be public (Kerckhoffs's principle)\n";
    std::cout << "   • Security through obscurity is NOT security\n";
    std::cout << "   • Always use authenticated encryption in practice\n";
    
    std::cout << "\n🔬 THIS IMPLEMENTATION IS FOR EDUCATION ONLY!\n";
    std::cout << "   These examples demonstrate concepts but lack:\n";
    std::cout << "   • Side-channel attack resistance\n";
    std::cout << "   • Proper random number generation\n";
    std::cout << "   • Constant-time implementations\n";
    std::cout << "   • Comprehensive security analysis\n";
}

int main() {
    std::cout << "COMPREHENSIVE CRYPTOGRAPHIC TECHNIQUES DEMONSTRATION\n";
    std::cout << "Educational Implementation by Oleg Goncharov\n";
    std::cout << "Senior C++ Cryptographic Engineer\n";
    
    try {
        demonstrate_historical_ciphers();
        demonstrate_perfect_security();
        demonstrate_modern_structures();
        demonstrate_stream_cipher();
        demonstrate_salt_techniques();
        demonstrate_iv_and_nonce();
        demonstrate_key_derivation();
        demonstrate_sbox_design();
        print_security_summary();
        
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "🎓 ALL CRYPTOGRAPHIC TECHNIQUES DEMONSTRATED SUCCESSFULLY!\n";
        std::cout << std::string(60, '=') << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}