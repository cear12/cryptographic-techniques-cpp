#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace educational_crypto {

// Feistel network: the structural pattern underlying DES, Blowfish, and
// (in generalized form) parts of Twofish. Splits an 8-byte block into two
// 4-byte halves and repeatedly applies a round function F to one half,
// XORing the result into the other -- a structure whose defining property
// is that encryption and decryption use the *same* round function, just
// with the round-key order reversed (see feistel_cipher.cpp for the proof
// sketch).
//
// IMPORTANT: as the demo output itself says, a Feistel network's security
// depends entirely on the quality of F and the round count. The F used here
// is a simple bit-mixing function (rotate + multiply + XOR-shift) chosen for
// clarity, not cryptanalytic strength -- it is NOT DES's F-function and this
// is NOT a secure cipher. See the repository README.
class FeistelCipher {
public:
    static constexpr int kRounds = 16;
    using Block = std::array<std::uint8_t, 8>;
    using KeySchedule = std::array<std::uint32_t, kRounds>;

    static KeySchedule generate_key_schedule(const std::vector<std::uint8_t>& masterKey);
    static Block encrypt(const Block& plaintext, const KeySchedule& keySchedule);
    static Block decrypt(const Block& ciphertext, const KeySchedule& keySchedule);
};

}  // namespace educational_crypto
