#include "cryptotech/salsa20.h"

#include <algorithm>
#include <cstring>

namespace educational_crypto {

namespace {

std::uint32_t rotl32(std::uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

std::uint32_t loadLe32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

void storeLe32(std::uint32_t v, std::uint8_t* p) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

void quarterRound(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
    b ^= rotl32(a + d, 7);
    c ^= rotl32(b + a, 9);
    d ^= rotl32(c + b, 13);
    a ^= rotl32(d + c, 18);
}

// Generates one 64-byte keystream block for the given key/nonce/block-counter.
// Layout follows the reference Salsa20 specification: constants at indices
// 0,5,10,15; key words at 1-4 and 11-14; nonce at 6-7; 64-bit little-endian
// block counter at 8-9.
std::array<std::uint8_t, 64> salsa20Block(const Salsa20::Key& key, const Salsa20::Nonce& nonce, std::uint64_t counter) {
    static constexpr std::uint32_t kSigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};  // "expand 32-byte k"

    std::array<std::uint32_t, 16> state{};
    state[0] = kSigma[0];
    state[1] = loadLe32(key.data() + 0);
    state[2] = loadLe32(key.data() + 4);
    state[3] = loadLe32(key.data() + 8);
    state[4] = loadLe32(key.data() + 12);
    state[5] = kSigma[1];
    state[6] = loadLe32(nonce.data() + 0);
    state[7] = loadLe32(nonce.data() + 4);
    state[8] = static_cast<std::uint32_t>(counter);
    state[9] = static_cast<std::uint32_t>(counter >> 32);
    state[10] = kSigma[2];
    state[11] = loadLe32(key.data() + 16);
    state[12] = loadLe32(key.data() + 20);
    state[13] = loadLe32(key.data() + 24);
    state[14] = loadLe32(key.data() + 28);
    state[15] = kSigma[3];

    std::array<std::uint32_t, 16> working = state;
    for (int round = 0; round < 10; ++round) {  // 10 double-rounds = 20 rounds total
        // Column rounds.
        quarterRound(working[0], working[4], working[8], working[12]);
        quarterRound(working[5], working[9], working[13], working[1]);
        quarterRound(working[10], working[14], working[2], working[6]);
        quarterRound(working[15], working[3], working[7], working[11]);
        // Row rounds.
        quarterRound(working[0], working[1], working[2], working[3]);
        quarterRound(working[5], working[6], working[7], working[4]);
        quarterRound(working[10], working[11], working[8], working[9]);
        quarterRound(working[15], working[12], working[13], working[14]);
    }

    std::array<std::uint8_t, 64> output{};
    for (int i = 0; i < 16; ++i) {
        std::uint32_t sum = working[static_cast<std::size_t>(i)] + state[static_cast<std::size_t>(i)];
        storeLe32(sum, output.data() + i * 4);
    }
    return output;
}

std::vector<std::uint8_t> xorWithKeystream(const std::vector<std::uint8_t>& data, const Salsa20::Key& key,
                                            const Salsa20::Nonce& nonce) {
    std::vector<std::uint8_t> out(data.size());
    std::uint64_t counter = 0;
    std::size_t offset = 0;
    while (offset < data.size()) {
        auto block = salsa20Block(key, nonce, counter++);
        std::size_t chunk = std::min<std::size_t>(64, data.size() - offset);
        for (std::size_t i = 0; i < chunk; ++i) out[offset + i] = static_cast<std::uint8_t>(data[offset + i] ^ block[i]);
        offset += chunk;
    }
    return out;
}

}  // namespace

std::vector<std::uint8_t> Salsa20::encrypt(const std::vector<std::uint8_t>& plaintext, const Key& key,
                                            const Nonce& nonce) {
    return xorWithKeystream(plaintext, key, nonce);
}

std::vector<std::uint8_t> Salsa20::decrypt(const std::vector<std::uint8_t>& ciphertext, const Key& key,
                                            const Nonce& nonce) {
    return xorWithKeystream(ciphertext, key, nonce);  // XOR stream cipher: decrypt == encrypt
}

}  // namespace educational_crypto
