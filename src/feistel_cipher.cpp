#include "cryptotech/feistel_cipher.h"

#include <bit>
#include <stdexcept>

namespace educational_crypto {

namespace {

std::uint32_t Rotl32(std::uint32_t x, int n) {
  // Was (x << n) | (x >> (32 - n)): for n == 0 that shifts by 32, which is UB
  // (UBSan: "shift exponent 32 is too large"). std::rotl handles every n.
  return std::rotl(x, n);
}

std::uint32_t BytesToWord(const std::uint8_t *b) {
  return (static_cast<std::uint32_t>(b[0]) << 24) |
         (static_cast<std::uint32_t>(b[1]) << 16) |
         (static_cast<std::uint32_t>(b[2]) << 8) |
         static_cast<std::uint32_t>(b[3]);
}

void WordToBytes(std::uint32_t w, std::uint8_t *b) {
  b[0] = static_cast<std::uint8_t>(w >> 24);
  b[1] = static_cast<std::uint8_t>(w >> 16);
  b[2] = static_cast<std::uint8_t>(w >> 8);
  b[3] = static_cast<std::uint8_t>(w);
}

// Toy round function -- see the header comment for why this is not (and is
// not trying to be) DES's F. Rotate + odd multiplicative constant + xor-shift
// is a cheap, reversible-looking (but not cryptographically vetted) way to
// diffuse bits of R combined with the round key.
std::uint32_t RoundFunction(std::uint32_t r, std::uint32_t round_key) {
  std::uint32_t x = r ^ round_key;
  x = Rotl32(x, 13);
  x *= 0x9E3779B1u; // fractional part of the golden ratio, scaled to 32 bits --
                    // a common integer-hash mixing constant
  x ^= (x >> 15);
  return x;
}

// One Feistel round: (L, R) -> (R, L XOR F(R, K)). Applying this kRounds
// times with keys in order, then swapping the two halves once at the end,
// is the encryption. Feeding the ciphertext back through the identical
// round function with the key order reversed undoes it exactly -- that is
// the entire point of a Feistel network.
void FeistelRound(std::uint32_t &l, std::uint32_t &r, std::uint32_t round_key) {
  std::uint32_t new_l = r;
  std::uint32_t new_r = l ^ RoundFunction(r, round_key);
  l = new_l;
  r = new_r;
}

} // namespace

FeistelCipher::KeySchedule FeistelCipher::GenerateKeySchedule(
    const std::vector<std::uint8_t> &master_key) {
  if (master_key.size() < 16) {
    throw std::invalid_argument("FeistelCipher::generate_key_schedule: master "
                                "key must be at least 16 bytes");
  }
  std::array<std::uint32_t, 4> words{};
  for (int i = 0; i < 4; ++i)
    words[static_cast<std::size_t>(i)] = BytesToWord(master_key.data() + i * 4);

  KeySchedule schedule{};
  for (int i = 0; i < kRounds; ++i) {
    std::uint32_t base = words[static_cast<std::size_t>(i % 4)];
    schedule[static_cast<std::size_t>(i)] =
        Rotl32(base, i % 32) ^ (static_cast<std::uint32_t>(i) * 0x9E3779B1u);
  }
  return schedule;
}

FeistelCipher::Block FeistelCipher::Encrypt(const Block &plaintext,
                                            const KeySchedule &key_schedule) {
  std::uint32_t l = BytesToWord(plaintext.data());
  std::uint32_t r = BytesToWord(plaintext.data() + 4);

  for (int i = 0; i < kRounds; ++i)
    FeistelRound(l, r, key_schedule[static_cast<std::size_t>(i)]);

  Block out{};
  // Final swap: output (R, L) rather than (L, R) -- see feistelRound() comment.
  WordToBytes(r, out.data());
  WordToBytes(l, out.data() + 4);
  return out;
}

FeistelCipher::Block FeistelCipher::Decrypt(const Block &ciphertext,
                                            const KeySchedule &key_schedule) {
  std::uint32_t l = BytesToWord(ciphertext.data());
  std::uint32_t r = BytesToWord(ciphertext.data() + 4);

  for (int i = kRounds - 1; i >= 0; --i)
    FeistelRound(l, r, key_schedule[static_cast<std::size_t>(i)]);

  Block out{};
  WordToBytes(r, out.data());
  WordToBytes(l, out.data() + 4);
  return out;
}

} // namespace educational_crypto
