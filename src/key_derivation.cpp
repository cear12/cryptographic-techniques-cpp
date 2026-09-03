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

std::vector<std::uint8_t> randomSalt(std::size_t length) {
    std::random_device rd;
    std::vector<std::uint8_t> salt(length);
    std::generate(salt.begin(), salt.end(), [&] { return static_cast<std::uint8_t>(rd()); });
    return salt;
}

std::vector<std::uint8_t> toBytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

DerivedKeys splitIntoKeys(const std::vector<std::uint8_t>& material, std::vector<std::uint8_t> salt,
                          std::uint32_t iterations) {
    DerivedKeys keys;
    keys.encryption_key.assign(material.begin(), material.begin() + static_cast<long>(kKeyLength));
    keys.mac_key.assign(material.begin() + static_cast<long>(kKeyLength), material.end());
    keys.salt = std::move(salt);
    keys.iterations = iterations;
    return keys;
}
}  // namespace

DerivedKeys KeyDerivationTechniques::derive_keys_pbkdf2(const std::string& password) {
    auto salt = randomSalt(16);
    auto material = cryptotech::pbkdf2HmacSha256(toBytes(password), salt, kPbkdf2Iterations, kTotalLength);
    return splitIntoKeys(material, salt, kPbkdf2Iterations);
}

DerivedKeys KeyDerivationTechniques::derive_keys_scrypt(const std::string& password) {
    auto salt = randomSalt(16);
    auto material = cryptotech::memoryHardKdf(toBytes(password), salt, kScryptCostFactor, kTotalLength);
    return splitIntoKeys(material, salt, kScryptCostFactor);
}

DerivedKeys KeyDerivationTechniques::derive_keys_hkdf(const std::vector<std::uint8_t>& shared_secret,
                                                       const std::vector<std::uint8_t>& context_info) {
    // No salt parameter in this call shape (matching the demo's usage,
    // which derives straight from an already-high-entropy shared secret) --
    // HKDF-Extract treats an empty salt as a string of zero bytes per RFC
    // 5869 section 2.2, which is a normal and documented usage mode.
    auto material = cryptotech::hkdfSha256({}, shared_secret, context_info, kTotalLength);
    return splitIntoKeys(material, {}, 0);
}

}  // namespace advanced_crypto
