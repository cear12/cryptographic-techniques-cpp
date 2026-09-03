#include "cryptotech/kdf.h"

#include <algorithm>

#include "cryptotech/sha256.h"

namespace cryptotech {

namespace {

std::vector<std::uint8_t> Be32(std::uint32_t v) {
  return {static_cast<std::uint8_t>(v >> 24),
          static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 8),
          static_cast<std::uint8_t>(v)};
}

} // namespace

std::vector<std::uint8_t>
Pbkdf2HmacSha256(const std::vector<std::uint8_t> &password,
                 const std::vector<std::uint8_t> &salt,
                 std::uint32_t iterations, std::size_t derived_key_length) {
  constexpr std::size_t kHashLen = Sha256::kDigestSize;
  std::vector<std::uint8_t> derived;
  derived.reserve(derived_key_length);

  for (std::uint32_t block_index = 1; derived.size() < derived_key_length;
       ++block_index) {
    // U1 = HMAC(password, salt || INT_32_BE(blockIndex))
    std::vector<std::uint8_t> u = salt;
    auto index_bytes = Be32(block_index);
    u.insert(u.end(), index_bytes.begin(), index_bytes.end());
    auto u_digest = HmacSha256(password, u);
    std::vector<std::uint8_t> t(u_digest.begin(), u_digest.end());

    // U2..Uc, XOR-accumulated into T.
    for (std::uint32_t i = 1; i < iterations; ++i) {
      u_digest = HmacSha256(password, std::vector<std::uint8_t>(
                                          u_digest.begin(), u_digest.end()));
      for (std::size_t b = 0; b < kHashLen; ++b)
        t[b] = static_cast<std::uint8_t>(t[b] ^ u_digest[b]);
    }

    std::size_t take = std::min(kHashLen, derived_key_length - derived.size());
    derived.insert(derived.end(), t.begin(),
                   t.begin() + static_cast<long>(take));
  }
  return derived;
}

std::vector<std::uint8_t> HkdfSha256(const std::vector<std::uint8_t> &salt,
                                     const std::vector<std::uint8_t> &ikm,
                                     const std::vector<std::uint8_t> &info,
                                     std::size_t output_length) {
  constexpr std::size_t kHashLen = Sha256::kDigestSize;

  // Extract: PRK = HMAC(salt, IKM). Per RFC 5869 section 2.2, an empty
  // salt is replaced with a string of kHashLen zero bytes.
  std::vector<std::uint8_t> effective_salt =
      salt.empty() ? std::vector<std::uint8_t>(kHashLen, 0x00) : salt;
  auto prk_digest = HmacSha256(effective_salt, ikm);
  std::vector<std::uint8_t> prk(prk_digest.begin(), prk_digest.end());

  // Expand: T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i); OKM = T(1) ||
  // T(2) || ...
  std::vector<std::uint8_t> okm;
  std::vector<std::uint8_t> previous_t;
  std::uint8_t counter = 1;
  while (okm.size() < output_length) {
    std::vector<std::uint8_t> input = previous_t;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(counter);

    auto t_digest = HmacSha256(prk, input);
    previous_t.assign(t_digest.begin(), t_digest.end());

    std::size_t take = std::min(kHashLen, output_length - okm.size());
    okm.insert(okm.end(), previous_t.begin(),
               previous_t.begin() + static_cast<long>(take));
    ++counter;
  }
  return okm;
}

std::vector<std::uint8_t>
MemoryHardKdf(const std::vector<std::uint8_t> &password,
              const std::vector<std::uint8_t> &salt, std::uint32_t cost_factor,
              std::size_t derived_key_length) {
  // Materialize a costFactor-entry buffer of 32-byte blocks, each derived
  // from the previous one by hashing -- a long, forced-sequential chain
  // that must live in memory in full before the final derivation step can
  // read scattered entries from it. This is the property that makes
  // memory-hard KDFs expensive to parallelize on ASICs/GPUs (limited,
  // fast, per-unit memory), unlike a plain iterated-hash KDF like PBKDF2.
  std::vector<Sha256::Digest> buffer(cost_factor);

  std::vector<std::uint8_t> seed_input = password;
  seed_input.insert(seed_input.end(), salt.begin(), salt.end());
  buffer[0] = Sha256::Hash(seed_input);
  for (std::uint32_t i = 1; i < cost_factor; ++i) {
    buffer[i] = Sha256::Hash(
        std::vector<std::uint8_t>(buffer[i - 1].begin(), buffer[i - 1].end()));
  }

  // Scattered-read mixing pass: fold in pseudorandom-indexed entries from
  // across the whole buffer, so the derivation genuinely depends on all of
  // it having been materialized (not just the last entry).
  Sha256::Digest mix_state = buffer.back();
  for (std::uint32_t round = 0; round < 64; ++round) {
    std::uint32_t index = 0;
    for (int b = 0; b < 4; ++b)
      index = (index << 8) | mix_state[static_cast<std::size_t>(b)];
    index %= cost_factor;

    std::vector<std::uint8_t> mix_input(mix_state.begin(), mix_state.end());
    mix_input.insert(mix_input.end(), buffer[index].begin(),
                     buffer[index].end());
    mix_state = Sha256::Hash(mix_input);
  }

  std::vector<std::uint8_t> final_input(mix_state.begin(), mix_state.end());
  final_input.insert(final_input.end(), password.begin(), password.end());
  return Pbkdf2HmacSha256(final_input, salt, 1, derived_key_length);
}

} // namespace cryptotech
