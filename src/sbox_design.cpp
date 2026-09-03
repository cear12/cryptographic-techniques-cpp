#include "cryptotech/sbox_design.h"

#include <algorithm>
#include <bit>
#include <numeric>
#include <random>

namespace advanced_crypto {

SBoxDesign::SBox SBoxDesign::GenerateRandomSbox() {
  SBox sbox{};
  std::iota(sbox.begin(), sbox.end(), 0);

  std::random_device rd;
  std::mt19937 rng(rd());
  std::shuffle(sbox.begin(), sbox.end(), rng);
  return sbox;
}

SBoxDesign::SBox SBoxDesign::CreateInverseSbox(const SBox &sbox) {
  SBox inverse{};
  for (int x = 0; x < 256; ++x) {
    inverse[sbox[static_cast<std::size_t>(x)]] = static_cast<std::uint8_t>(x);
  }
  return inverse;
}

namespace {
// Parity (0 or 1) of the bitwise AND of a and b, i.e. the dot product of
// their bit vectors over GF(2). Used to evaluate the "component" linear
// functions a.F(x) and b.x that the Walsh-Hadamard transform correlates.
int DotParity(unsigned a, unsigned b) { return std::popcount(a & b) & 1; }

// Walsh-Hadamard coefficient W(a,b) = sum_x (-1)^{a.F(x) xor b.x}, summed
// over all 256 inputs x. a selects which output-bit combination to look at
// (must be nonzero -- a=0 is the trivial all-agreeing case); b selects
// which input-bit combination to correlate it against.
int WalshCoefficient(const SBoxDesign::SBox &sbox, unsigned a, unsigned b) {
  int sum = 0;
  for (unsigned x = 0; x < 256; ++x) {
    int exponent = DotParity(a, sbox[x]) ^ DotParity(b, x);
    sum += exponent ? -1 : 1;
  }
  return sum;
}
} // namespace

double SBoxDesign::CalculateNonlinearity(const SBox &sbox) {
  int max_abs_walsh = 0;
  for (unsigned a = 1; a < 256; ++a) {   // nonzero output masks only
    for (unsigned b = 0; b < 256; ++b) { // all input masks
      max_abs_walsh =
          std::max(max_abs_walsh, std::abs(WalshCoefficient(sbox, a, b)));
    }
  }
  // NL(F) = 2^(n-1) - max|W(a,b)| / 2, for n = 8 input bits.
  return 128.0 - static_cast<double>(max_abs_walsh) / 2.0;
}

int SBoxDesign::CalculateDifferentialUniformity(const SBox &sbox) {
  int max_count = 0;
  for (unsigned dx = 1; dx < 256; ++dx) {
    std::array<int, 256> counts{};
    for (unsigned x = 0; x < 256; ++x) {
      std::uint8_t dy = static_cast<std::uint8_t>(sbox[x] ^ sbox[x ^ dx]);
      ++counts[dy];
    }
    max_count =
        std::max(max_count, *std::max_element(counts.begin(), counts.end()));
  }
  return max_count;
}

} // namespace advanced_crypto
