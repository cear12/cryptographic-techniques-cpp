# cryptographic-techniques-cpp

A tour of classic and modern cryptographic building blocks, implemented
from their public specifications with zero third-party dependencies (no
OpenSSL, no libsodium). Written for **education**: it exists to show how
these primitives actually work internally, not to be used in place of a
vetted crypto library. See "Status and limitations" below before using any
of this for anything beyond reading and experimentation.

Every primitive that has a widely-cited known-answer test vector is checked
against it at program startup (`examples/demo.cpp` prints PASS/FAIL for
each before running the rest of the demo, and exits non-zero if any check
fails), so a regression can never silently produce plausible-looking wrong
output.

## Modules

| Namespace | Class | What it demonstrates |
|---|---|---|
| `educational_crypto` | `CaesarCipher`, `SubstitutionCipher`, `VigenereCipher` | Historical ciphers, broken by frequency analysis -- included for context, not security. |
| `educational_crypto` | `OneTimePad` | The one cipher here with an actual proof of perfect secrecy (Shannon, 1949), provided the key is truly random, as long as the message, used once, and secret. |
| `educational_crypto` | `FeistelCipher` | The Feistel network structure underlying DES/Blowfish. Uses a **toy round function**, not DES's F -- see the header comment. |
| `educational_crypto` | `Salsa20` | A real, from-specification Salsa20 stream cipher (the design ChaCha20 descends from), verified against an official ECRYPT test vector. |
| `advanced_crypto` | `SaltTechniques` | Salted, iterated password hashing (PBKDF2-HMAC-SHA256) and constant-time-ish verification. |
| `advanced_crypto` | `IVandNonceTechniques` | AES-128 in CBC, CTR, and an authenticated "GCM-style" mode -- **see the honesty note below**. |
| `advanced_crypto` | `KeyDerivationTechniques` | PBKDF2, a simplified memory-hard KDF, and HKDF (RFC 5869), each suited to a different kind of input key material. |
| `advanced_crypto` | `SBoxDesign` | Generates and cryptanalyzes 8-bit S-boxes: nonlinearity (Walsh-Hadamard transform) and differential uniformity (difference distribution table). |

Underneath these, `cryptotech::Sha256`/`hmacSha256`, `cryptotech::Aes128`,
and `cryptotech::pbkdf2HmacSha256`/`hkdfSha256`/`memoryHardKdf` are the
from-scratch primitives everything else is built from.

## Known-answer tests

| Primitive | Vector source | Result |
|---|---|---|
| AES-128 | FIPS-197 Appendix B | exact match |
| SHA-256 | `SHA-256("")` | exact match |
| Salsa20 | ECRYPT `test_vectors.256`, Set 1 vector #0 | exact match |
| PBKDF2-HMAC-SHA256, HKDF-SHA256 | derived from RFC 8018 / RFC 5869 structure directly against this repo's own (separately, RFC 4231-verified) HMAC-SHA256 | self-consistent |
| Feistel network | none published (custom toy F-function) | round-trip correctness only |

The AES-128 **S-box itself is not a hard-coded table** -- it's generated at
runtime from its actual mathematical definition (multiplicative inverse in
GF(2^8), then the FIPS-197 affine transform). That was a deliberate choice:
a 256-byte constant copied from a reference is one transposed digit away
from being silently wrong, while generating it from the definition either
produces the right answer or fails the FIPS-197 known-answer test loudly.

## Honesty notes (please read before reusing any of this)

- **"GCM-style" is not AES-GCM.** Real AES-GCM authenticates with GHASH, a
  GF(2^128) polynomial MAC, which is not implemented here. What *is*
  implemented is a standard Encrypt-then-MAC construction -- AES-128-CTR,
  then HMAC-SHA256 over nonce/AAD/ciphertext -- that provides the same three
  properties (confidentiality, integrity, associated-data authentication)
  through a different, simpler, equally legitimate construction. It is not
  byte-compatible with real AES-GCM.
- **"scrypt-style" is not RFC 7914 scrypt.** Real scrypt's ROMix/BlockMix
  construction over a Salsa20/8 core is a substantial undertaking on its
  own. `cryptotech::memoryHardKdf` preserves scrypt's *core idea* --
  materialize a large pseudorandom buffer and force the final output to
  depend on scattered reads across all of it, so memory can't be traded away
  for time the way it can against PBKDF2 -- without being a byte-exact
  implementation.
- **The Feistel round function is a toy.** Rotate + multiply + xor-shift,
  chosen for clarity. It is not DES's F, has not been cryptanalyzed, and the
  resulting cipher should not be assumed secure.
- **`std::random_device` is used as the randomness source** for salts, IVs,
  nonces, and the one-time pad key. Most standard library implementations
  back it with real OS entropy, but the C++ standard does not *require*
  that, so production code should call a platform CSPRNG API directly.
- **No side-channel hardening.** These implementations are written for
  correctness and clarity, not for resistance to cache-timing or other
  side-channel attacks.

The practical upshot, echoed at the end of the demo's own output: don't
implement crypto yourself for production use. Use OpenSSL, libsodium, or
Botan, and keep this repo for what it's for -- understanding how the pieces
underneath those libraries actually work.

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/examples/crypto_demo
```

CMake option `CRYPTOTECH_BUILD_EXAMPLES` (default `ON`) builds
`examples/crypto_demo`.

There is no separate Catch2 test suite in this repo -- the demo's own
startup self-checks (see above) serve as the regression test, and CI runs
the demo as its verification step.
