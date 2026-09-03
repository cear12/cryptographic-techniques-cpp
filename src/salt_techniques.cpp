#include "cryptotech/salt_techniques.h"

#include <algorithm>
#include <random>

#include "cryptotech/kdf.h"

namespace advanced_crypto {

namespace {
constexpr std::size_t kSaltLength = 16;
constexpr std::size_t kHashLength = 32;
constexpr std::uint32_t kIterations = 100'000;  // OWASP-ballpark PBKDF2-HMAC-SHA256 minimum as of the mid-2020s

std::vector<std::uint8_t> randomSalt() {
    std::random_device rd;
    std::vector<std::uint8_t> salt(kSaltLength);
    std::generate(salt.begin(), salt.end(), [&] { return static_cast<std::uint8_t>(rd()); });
    return salt;
}

std::vector<std::uint8_t> toBytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
}  // namespace

PasswordHash SaltTechniques::hash_password(const std::string& password) {
    PasswordHash result;
    result.salt = randomSalt();
    result.iterations = kIterations;
    result.hash = cryptotech::pbkdf2HmacSha256(toBytes(password), result.salt, result.iterations, kHashLength);
    return result;
}

bool SaltTechniques::verify_password(const std::string& password, const PasswordHash& stored) {
    auto candidate = cryptotech::pbkdf2HmacSha256(toBytes(password), stored.salt, stored.iterations, stored.hash.size());
    // Constant-time-ish comparison: always scan the full length rather than
    // short-circuiting on the first mismatch, so a timing side-channel
    // cannot leak how many leading bytes matched. (Not a hardened
    // constant-time primitive -- see the repository README.)
    if (candidate.size() != stored.hash.size()) return false;
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < candidate.size(); ++i) diff |= static_cast<std::uint8_t>(candidate[i] ^ stored.hash[i]);
    return diff == 0;
}

}  // namespace advanced_crypto
