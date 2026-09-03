#include "cryptotech/salt_techniques.h"

#include <algorithm>
#include <random>

#include "cryptotech/kdf.h"

namespace advanced_crypto {

namespace {
constexpr std::size_t kSaltLength = 16;
constexpr std::size_t kHashLength = 32;
constexpr std::uint32_t kIterations =
    100'000; // OWASP-ballpark PBKDF2-HMAC-SHA256 minimum as of the mid-2020s

std::vector<std::uint8_t> RandomSalt() {
  std::random_device rd;
  std::vector<std::uint8_t> salt(kSaltLength);
  std::generate(salt.begin(), salt.end(),
                [&] { return static_cast<std::uint8_t>(rd()); });
  return salt;
}

std::vector<std::uint8_t> ToBytes(const std::string &s) {
  return std::vector<std::uint8_t>(s.begin(), s.end());
}
} // namespace

PasswordHash SaltTechniques::HashPassword(const std::string &password) {
  PasswordHash result;
  result.salt_ = RandomSalt();
  result.iterations_ = kIterations;
  result.hash_ = cryptotech::Pbkdf2HmacSha256(ToBytes(password), result.salt_,
                                              result.iterations_, kHashLength);
  return result;
}

bool SaltTechniques::VerifyPassword(const std::string &password,
                                    const PasswordHash &stored) {
  auto candidate = cryptotech::Pbkdf2HmacSha256(
      ToBytes(password), stored.salt_, stored.iterations_, stored.hash_.size());
  // Constant-time-ish comparison: always scan the full length rather than
  // short-circuiting on the first mismatch, so a timing side-channel
  // cannot leak how many leading bytes matched. (Not a hardened
  // constant-time primitive -- see the repository README.)
  if (candidate.size() != stored.hash_.size())
    return false;
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < candidate.size(); ++i)
    diff |= static_cast<std::uint8_t>(candidate[i] ^ stored.hash_[i]);
  return diff == 0;
}

} // namespace advanced_crypto
