#pragma once

#include <array>
#include <cstdint>

namespace cryptotech {

// Self-contained AES-128 (FIPS-197) single-block encrypt/decrypt.
//
// The S-box is not hard-coded from a lookup table; it is generated at
// static-initialization time from its actual mathematical definition
// (multiplicative inverse in GF(2^8), reduction polynomial x^8+x^4+x^3+x+1,
// followed by the FIPS-197 affine transform). This avoids the classic
// transcription-error risk of copy-pasting a 256-byte constant table, and
// the result is checked against the official FIPS-197 Appendix B
// known-answer test in demo startup self-checks.
//
// Zero third-party dependencies (no OpenSSL). Written for clarity, not for
// constant-time resistance to cache-timing side channels -- see the
// repository README for the "do not use this for production" disclaimer.
class Aes128 {
public:
    static constexpr std::size_t kBlockSize = 16;
    static constexpr std::size_t kKeySize = 16;
    using Block = std::array<std::uint8_t, kBlockSize>;
    using Key = std::array<std::uint8_t, kKeySize>;

    explicit Aes128(const Key& key);

    Block encryptBlock(const Block& plaintext) const;
    Block decryptBlock(const Block& ciphertext) const;

private:
    static constexpr int kRounds = 10;
    // 4 words/round-key * (Nr+1) round keys, 4 bytes/word.
    std::array<std::uint8_t, 4 * 4 * (kRounds + 1)> roundKeys_{};

    void expandKey(const Key& key);
};

}  // namespace cryptotech
