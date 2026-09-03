#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace advanced_crypto {

struct DerivedKeys {
    std::vector<std::uint8_t> encryption_key_;
    std::vector<std::uint8_t> mac_key_;
    std::vector<std::uint8_t> salt_;
    std::uint32_t iterations_ = 0;  // meaning depends on the deriving function: PBKDF2 iteration count, or memory-hard cost factor
};

// Three ways to turn key material into one or more independent, fixed-size
// keys, each suited to a different starting point:
//   - DeriveKeysPbkdf2 / DeriveKeysScrypt: password -> keys (low
//     starting entropy, so both deliberately cost CPU time and/or memory).
//   - DeriveKeysHkdf: shared secret -> keys (already high entropy, e.g.
//     an ECDH output, so no cost-inflation is needed -- HKDF is cheap by
//     design and instead focuses on clean domain separation between the
//     multiple keys derived from one secret).
class KeyDerivationTechniques {
public:
    static DerivedKeys DeriveKeysPbkdf2(const std::string& password);
    // See cryptotech::memoryHardKdf for the honest scope of what "scrypt"
    // means here -- a simplified, non-byte-exact stand-in.
    static DerivedKeys DeriveKeysScrypt(const std::string& password);
    static DerivedKeys DeriveKeysHkdf(const std::vector<std::uint8_t>& shared_secret,
                                         const std::vector<std::uint8_t>& context_info);
};

}  // namespace advanced_crypto
