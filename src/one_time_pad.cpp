#include "cryptotech/one_time_pad.h"

#include <algorithm>
#include <random>
#include <stdexcept>

namespace educational_crypto {

std::vector<std::uint8_t> OneTimePad::GenerateKey(std::size_t length) {
  std::random_device rd;
  std::vector<std::uint8_t> key(length);
  std::generate(key.begin(), key.end(),
                [&] { return static_cast<std::uint8_t>(rd()); });
  return key;
}

namespace {
std::vector<std::uint8_t> XorWithKey(const std::vector<std::uint8_t> &data,
                                     const std::vector<std::uint8_t> &key) {
  if (data.size() != key.size()) {
    throw std::invalid_argument(
        "OneTimePad: key length must equal message length");
  }
  std::vector<std::uint8_t> out(data.size());
  for (std::size_t i = 0; i < data.size(); ++i)
    out[i] = static_cast<std::uint8_t>(data[i] ^ key[i]);
  return out;
}
} // namespace

std::vector<std::uint8_t>
OneTimePad::Encrypt(const std::vector<std::uint8_t> &plaintext,
                    const std::vector<std::uint8_t> &key) {
  return XorWithKey(plaintext, key);
}

std::vector<std::uint8_t>
OneTimePad::Decrypt(const std::vector<std::uint8_t> &ciphertext,
                    const std::vector<std::uint8_t> &key) {
  return XorWithKey(ciphertext, key); // XOR is its own inverse
}

} // namespace educational_crypto
