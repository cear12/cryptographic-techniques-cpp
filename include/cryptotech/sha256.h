#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace cryptotech {

// Self-contained SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104).
//
// This repository has zero third-party dependencies, so instead of linking
// OpenSSL it vendors a small, from-scratch implementation of the one hash
// primitive the higher-level demos (salting, PBKDF2, HKDF) build on. It is
// written for clarity and correctness on small inputs (test/demo data), not
// for constant-time resistance to timing side-channels -- production code
// protecting real secrets should link a vetted library (OpenSSL, BoringSSL,
// libsodium, ...) instead. See the repository README for the full
// "do not use this for production" disclaimer.
class Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;
    using Digest = std::array<std::uint8_t, kDigestSize>;

    Sha256();

    void update(const std::uint8_t* data, std::size_t length);
    void update(const std::vector<std::uint8_t>& data);

    // Finalizes and returns the digest. The object must not be reused
    // after calling this.
    Digest finish();

    static Digest hash(const std::vector<std::uint8_t>& data);
    static std::string toHex(const Digest& digest);

private:
    void processBlock(const std::uint8_t* block);

    std::array<std::uint32_t, 8> state_;
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t bufferLength_ = 0;
    std::uint64_t totalLength_ = 0;
};

// HMAC-SHA256(key, message) per RFC 2104.
Sha256::Digest hmacSha256(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& message);

}  // namespace cryptotech
