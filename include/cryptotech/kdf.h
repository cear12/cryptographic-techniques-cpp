#pragma once

#include <cstdint>
#include <vector>

namespace cryptotech {

// PBKDF2-HMAC-SHA256 (RFC 8018). Iterates HMAC to deliberately slow down
// brute-force search of low-entropy passwords.
std::vector<std::uint8_t> Pbkdf2HmacSha256(const std::vector<std::uint8_t>& password,
                                            const std::vector<std::uint8_t>& salt, std::uint32_t iterations,
                                            std::size_t derived_key_length);

// HKDF-SHA256 (RFC 5869), Extract-then-Expand. Used to turn a shared secret
// with good entropy (e.g. an ECDH output) into one or more uniform,
// independent keys -- NOT meant for stretching low-entropy passwords (use
// pbkdf2HmacSha256 or memoryHardKdf for that).
std::vector<std::uint8_t> HkdfSha256(const std::vector<std::uint8_t>& salt, const std::vector<std::uint8_t>& ikm,
                                      const std::vector<std::uint8_t>& info, std::size_t output_length);

// A simplified stand-in for a memory-hard KDF (the role scrypt/Argon2 play).
// It is deliberately NOT a byte-exact RFC 7914 scrypt implementation --
// real scrypt's ROMix/BlockMix/Salsa20-8 construction is a substantial
// undertaking of its own. What this function preserves is scrypt's *core
// idea*: materialize a large pseudorandom buffer (sized by costFactor) in
// memory and then make the output depend on scattered reads across the
// whole buffer, so an attacker cannot trade memory for time the way they
// can against PBKDF2. See the repository README for the honest scope of
// this simplification.
std::vector<std::uint8_t> MemoryHardKdf(const std::vector<std::uint8_t>& password,
                                         const std::vector<std::uint8_t>& salt, std::uint32_t cost_factor,
                                         std::size_t derived_key_length);

}  // namespace cryptotech
