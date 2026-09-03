#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace advanced_crypto {

struct PasswordHash {
    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> hash;
    std::uint32_t iterations = 0;
};

// Salted, iterated password hashing (PBKDF2-HMAC-SHA256 under the hood --
// see cryptotech::pbkdf2HmacSha256). A fresh random salt per call means
// hashing the same password twice yields two different hashes, which is
// exactly what defeats precomputed rainbow-table attacks.
class SaltTechniques {
public:
    static PasswordHash hash_password(const std::string& password);
    static bool verify_password(const std::string& password, const PasswordHash& stored);
};

}  // namespace advanced_crypto
