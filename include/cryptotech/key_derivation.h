#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace advanced_crypto {

struct DerivedKeys {
    std::vector<std::uint8_t> encryption_key;
    std::vector<std::uint8_t> mac_key;
    std::vector<std::uint8_t> salt;
    std::uint32_t iterations = 0;  // meaning depends on the deriving function: PBKDF2 iteration count, or memory-hard cost factor
};

// Three ways to turn key material into one or more independent, fixed-size
// keys, each suited to a different starting point:
//   - derive_keys_pbkdf2 / derive_keys_scrypt: password -> keys (low
//     starting entropy, so both deliberately cost CPU time and/or memory).
//   - derive_keys_hkdf: shared secret -> keys (already high entropy, e.g.
//     an ECDH output, so no cost-inflation is needed -- HKDF is cheap by
//     design and instead focuses on clean domain separation between the
//     multiple keys derived from one secret).
class KeyDerivationTechniques {
public:
    static DerivedKeys derive_keys_pbkdf2(const std::string& password);
    // See cryptotech::memoryHardKdf for the honest scope of what "scrypt"
    // means here -- a simplified, non-byte-exact stand-in.
    static DerivedKeys derive_keys_scrypt(const std::string& password);
    static DerivedKeys derive_keys_hkdf(const std::vector<std::uint8_t>& shared_secret,
                                         const std::vector<std::uint8_t>& context_info);
};

}  // namespace advanced_crypto
