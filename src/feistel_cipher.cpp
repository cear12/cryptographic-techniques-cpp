#include "cryptotech/feistel_cipher.h"

#include <stdexcept>

namespace educational_crypto {

namespace {

std::uint32_t rotl32(std::uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

std::uint32_t bytesToWord(const std::uint8_t* b) {
    return (static_cast<std::uint32_t>(b[0]) << 24) | (static_cast<std::uint32_t>(b[1]) << 16) |
           (static_cast<std::uint32_t>(b[2]) << 8) | static_cast<std::uint32_t>(b[3]);
}

void wordToBytes(std::uint32_t w, std::uint8_t* b) {
    b[0] = static_cast<std::uint8_t>(w >> 24);
    b[1] = static_cast<std::uint8_t>(w >> 16);
    b[2] = static_cast<std::uint8_t>(w >> 8);
    b[3] = static_cast<std::uint8_t>(w);
}

// Toy round function -- see the header comment for why this is not (and is
// not trying to be) DES's F. Rotate + odd multiplicative constant + xor-shift
// is a cheap, reversible-looking (but not cryptographically vetted) way to
// diffuse bits of R combined with the round key.
std::uint32_t roundFunction(std::uint32_t r, std::uint32_t roundKey) {
    std::uint32_t x = r ^ roundKey;
    x = rotl32(x, 13);
    x *= 0x9E3779B1u;  // fractional part of the golden ratio, scaled to 32 bits -- a common integer-hash mixing constant
    x ^= (x >> 15);
    return x;
}

// One Feistel round: (L, R) -> (R, L XOR F(R, K)). Applying this kRounds
// times with keys in order, then swapping the two halves once at the end,
// is the encryption. Feeding the ciphertext back through the identical
// round function with the key order reversed undoes it exactly -- that is
// the entire point of a Feistel network.
void feistelRound(std::uint32_t& l, std::uint32_t& r, std::uint32_t roundKey) {
    std::uint32_t newL = r;
    std::uint32_t newR = l ^ roundFunction(r, roundKey);
    l = newL;
    r = newR;
}

}  // namespace

FeistelCipher::KeySchedule FeistelCipher::generate_key_schedule(const std::vector<std::uint8_t>& masterKey) {
    if (masterKey.size() < 16) {
        throw std::invalid_argument("FeistelCipher::generate_key_schedule: master key must be at least 16 bytes");
    }
    std::array<std::uint32_t, 4> words{};
    for (int i = 0; i < 4; ++i) words[static_cast<std::size_t>(i)] = bytesToWord(masterKey.data() + i * 4);

    KeySchedule schedule{};
    for (int i = 0; i < kRounds; ++i) {
        std::uint32_t base = words[static_cast<std::size_t>(i % 4)];
        schedule[static_cast<std::size_t>(i)] =
            rotl32(base, i % 32) ^ (static_cast<std::uint32_t>(i) * 0x9E3779B1u);
    }
    return schedule;
}

FeistelCipher::Block FeistelCipher::encrypt(const Block& plaintext, const KeySchedule& keySchedule) {
    std::uint32_t l = bytesToWord(plaintext.data());
    std::uint32_t r = bytesToWord(plaintext.data() + 4);

    for (int i = 0; i < kRounds; ++i) feistelRound(l, r, keySchedule[static_cast<std::size_t>(i)]);

    Block out{};
    // Final swap: output (R, L) rather than (L, R) -- see feistelRound() comment.
    wordToBytes(r, out.data());
    wordToBytes(l, out.data() + 4);
    return out;
}

FeistelCipher::Block FeistelCipher::decrypt(const Block& ciphertext, const KeySchedule& keySchedule) {
    std::uint32_t l = bytesToWord(ciphertext.data());
    std::uint32_t r = bytesToWord(ciphertext.data() + 4);

    for (int i = kRounds - 1; i >= 0; --i) feistelRound(l, r, keySchedule[static_cast<std::size_t>(i)]);

    Block out{};
    wordToBytes(r, out.data());
    wordToBytes(l, out.data() + 4);
    return out;
}

}  // namespace educational_crypto
