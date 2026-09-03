#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace advanced_crypto {

struct PasswordHash {
  std::vector<std::uint8_t> salt_;
  std::vector<std::uint8_t> hash_;
  std::uint32_t iterations_ = 0;
};

// Salted, iterated password hashing (PBKDF2-HMAC-SHA256 under the hood --
// see cryptotech::pbkdf2HmacSha256). A fresh random salt per call means
// hashing the same password twice yields two different hashes, which is
// exactly what defeats precomputed rainbow-table attacks.
class SaltTechniques {
public:
  static PasswordHash HashPassword(const std::string &password);
  static bool VerifyPassword(const std::string &password,
                             const PasswordHash &stored);
};

} // namespace advanced_crypto
