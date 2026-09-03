#include "cryptotech/key_derivation.h"

#include <algorithm>
#include <random>

#include "cryptotech/kdf.h"

namespace advanced_crypto {

namespace {
constexpr std::size_t kKeyLength = 32;      // each of encryption_key / mac_key
constexpr std::size_t kTotalLength = kKeyLength * 2;
constexpr std::uint32_t kPbkdf2Iterations = 100'000;
constexpr std::uint32_t kScryptCostFactor = 16'384;  // 2^14, a common scrypt N default

std::vector<std::uint8_t> RandomSalt(std::size_t length) {
    std::random_device rd;
    std::vector<std::uint8_t> salt(length);
    std::generate(salt.begin(), salt.end(), [&] { return static_cast<std::uint8_t>(rd()); });
    return salt;
}

std::vector<std::uint8_t> ToBytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

DerivedKeys SplitIntoKeys(const std::vector<std::uint8_t>& material, std::vector<std::uint8_t> salt,
                          std::uint32_t iterations) {
    DerivedKeys keys;
    keys.encryption_key_.assign(material.begin(), material.begin() + static_cast<long>(kKeyLength));
    keys.mac_key_.assign(material.begin() + static_cast<long>(kKeyLength), material.end());
    keys.salt_ = std::move(salt);
    keys.iterations_ = iterations;
    return keys;
}
}  // namespace

DerivedKeys KeyDerivationTechniques::DeriveKeysPbkdf2(const std::string& password) {
    auto salt = RandomSalt(16);
    auto material = cryptotech::Pbkdf2HmacSha256(ToBytes(password), salt, kPbkdf2Iterations, kTotalLength);
    return SplitIntoKeys(material, salt, kPbkdf2Iterations);
}

DerivedKeys KeyDerivationTechniques::DeriveKeysScrypt(const std::string& password) {
    auto salt = RandomSalt(16);
    auto material = cryptotech::MemoryHardKdf(ToBytes(password), salt, kScryptCostFactor, kTotalLength);
    return SplitIntoKeys(material, salt, kScryptCostFactor);
}

DerivedKeys KeyDerivationTechniques::DeriveKeysHkdf(const std::vector<std::uint8_t>& shared_secret,
                                                       const std::vector<std::uint8_t>& context_info) {
    // No salt parameter in this call shape (matching the demo's usage,
    // which derives straight from an already-high-entropy shared secret) --
    // HKDF-Extract treats an empty salt as a string of zero bytes per RFC
    // 5869 section 2.2, which is a normal and documented usage mode.
    auto material = cryptotech::HkdfSha256({}, shared_secret, context_info, kTotalLength);
    return SplitIntoKeys(material, {}, 0);
}

}  // namespace advanced_crypto
