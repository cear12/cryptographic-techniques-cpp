#pragma once

#include <cstdint>
#include <vector>

namespace educational_crypto {

// One-time pad: XOR with a truly random key of the same length as the
// message. The only cipher in this repository with an actual proof of
// perfect secrecy (Shannon, 1949) -- provided the key is truly random, used
// exactly once, kept secret, and at least as long as the message. Violate
// any one of those and the "perfect" guarantee disappears completely.
class OneTimePad {
public:
    static std::vector<std::uint8_t> generate_key(std::size_t length);
    static std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& plaintext,
                                              const std::vector<std::uint8_t>& key);
    static std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& ciphertext,
                                              const std::vector<std::uint8_t>& key);
};

}  // namespace educational_crypto
