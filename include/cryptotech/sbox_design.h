#pragma once

#include <array>
#include <cstdint>

namespace advanced_crypto {

// Tools for generating and analyzing 8-bit substitution boxes (S-boxes),
// the nonlinear building block that gives block ciphers "confusion" in
// Shannon's sense. AES, DES, Blowfish, Twofish, and most other block
// ciphers all center on one.
class SBoxDesign {
public:
    using SBox = std::array<std::uint8_t, 256>;

    // A uniformly random bijective S-box (Fisher-Yates shuffle of the
    // identity permutation). Cryptographically meaningful S-box design
    // (like AES's, built from a GF(2^8) inverse + affine transform -- see
    // cryptotech::Aes128) chooses structure deliberately to optimize the
    // properties below; a *random* permutation is a useful baseline to
    // measure real designs against, not a design recommendation itself.
    static SBox generate_random_sbox();

    // Valid only for a bijective S-box: inverse[sbox[x]] == x for all x.
    static SBox create_inverse_sbox(const SBox& sbox);

    // Nonlinearity: how far the S-box's component Boolean functions are
    // from any affine function, via the Walsh-Hadamard transform. Higher is
    // better (more resistant to linear cryptanalysis). The theoretical
    // maximum for a bijective 8-bit S-box is 112 -- AES's S-box achieves it.
    static double calculate_nonlinearity(const SBox& sbox);

    // Differential uniformity: the largest entry in the S-box's difference
    // distribution table, i.e. max over nonzero input differences dx and
    // all output differences dy of |{x : S(x) xor S(x xor dx) == dy}|.
    // Lower is better (more resistant to differential cryptanalysis). AES's
    // S-box achieves the optimal value of 4 for a bijective 8-bit S-box.
    static int calculate_differential_uniformity(const SBox& sbox);
};

}  // namespace advanced_crypto
