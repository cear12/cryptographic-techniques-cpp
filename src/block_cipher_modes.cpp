#include "cryptotech/block_cipher_modes.h"

#include <algorithm>
#include <random>
#include <stdexcept>

#include "cryptotech/aes128.h"
#include "cryptotech/sha256.h"

namespace cryptotech {

namespace {

// std::random_device is not guaranteed to be a CSPRNG on every standard
// library, but in practice (libstdc++, libc++, MSVC STL) it reads from the
// OS entropy source. That is good enough for this educational demo; real
// products should use a platform CSPRNG API directly (getrandom(2),
// BCryptGenRandom, arc4random_buf, ...).
std::vector<std::uint8_t> RandomBytes(std::size_t count) {
    std::random_device rd;
    std::vector<std::uint8_t> bytes(count);
    std::generate(bytes.begin(), bytes.end(), [&] { return static_cast<std::uint8_t>(rd()); });
    return bytes;
}

// Reduces an arbitrary-length key to a 16-byte AES-128 key. Domain-separated
// from macKeyFor() below via a trailing tag byte, so the encryption and MAC
// keys used by encryptGcmStyle()/decryptGcmStyle() are independent even
// though they are both derived from the same caller-supplied key material.
Aes128::Key EncKeyFor(const std::vector<std::uint8_t>& key) {
    std::vector<std::uint8_t> tagged = key;
    tagged.push_back('E');
    auto digest = Sha256::Hash(tagged);
    Aes128::Key aes_key{};
    std::copy(digest.begin(), digest.begin() + static_cast<long>(aes_key.size()), aes_key.begin());
    return aes_key;
}

std::vector<std::uint8_t> MacKeyFor(const std::vector<std::uint8_t>& key) {
    std::vector<std::uint8_t> tagged = key;
    tagged.push_back('M');
    auto digest = Sha256::Hash(tagged);
    return std::vector<std::uint8_t>(digest.begin(), digest.end());
}

void XorBlock(std::uint8_t* out, const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) out[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
}

// CTR keystream: encrypts nonce||counter for each 16-byte block and XORs it
// with the input. Symmetric -- the same function does both directions.
std::vector<std::uint8_t> CtrXor(const Aes128& aes, const std::vector<std::uint8_t>& nonce,
                                  const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> out(data.size());
    Aes128::Block counter_block{};
    std::copy(nonce.begin(), nonce.end(), counter_block.begin());  // nonce occupies the low bytes; upper bytes start at 0

    std::size_t offset = 0;
    std::uint64_t counter = 0;
    while (offset < data.size()) {
        // Store the 64-bit counter in the last 8 bytes of the block, big-endian.
        for (int i = 0; i < 8; ++i) {
            counter_block[static_cast<std::size_t>(15 - i)] = static_cast<std::uint8_t>(counter >> (8 * i));
        }
        Aes128::Block keystream = aes.EncryptBlock(counter_block);

        std::size_t chunk = std::min<std::size_t>(16, data.size() - offset);
        XorBlock(out.data() + offset, data.data() + offset, keystream.data(), chunk);

        offset += chunk;
        ++counter;
    }
    return out;
}

}  // namespace

CipherResult BlockCipherModes::EncryptCbcWithIv(const std::vector<std::uint8_t>& plaintext,
                                                 const std::vector<std::uint8_t>& key) {
    Aes128 aes(EncKeyFor(key));

    // PKCS#7 padding up to a multiple of the 16-byte block size.
    std::vector<std::uint8_t> padded = plaintext;
    std::uint8_t pad_value = static_cast<std::uint8_t>(16 - (plaintext.size() % 16));
    padded.insert(padded.end(), pad_value, pad_value);

    auto iv = RandomBytes(16);
    CipherResult result;
    result.iv_or_nonce_ = iv;
    result.ciphertext_.resize(padded.size());

    Aes128::Block previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());

    for (std::size_t offset = 0; offset < padded.size(); offset += 16) {
        Aes128::Block block{};
        std::copy(padded.begin() + static_cast<long>(offset), padded.begin() + static_cast<long>(offset) + 16, block.begin());
        XorBlock(block.data(), block.data(), previous.data(), 16);
        Aes128::Block encrypted = aes.EncryptBlock(block);
        std::copy(encrypted.begin(), encrypted.end(), result.ciphertext_.begin() + static_cast<long>(offset));
        previous = encrypted;
    }
    return result;
}

std::vector<std::uint8_t> BlockCipherModes::DecryptCbcWithIv(const CipherResult& in,
                                                               const std::vector<std::uint8_t>& key) {
    if (in.ciphertext_.empty() || in.ciphertext_.size() % 16 != 0 || in.iv_or_nonce_.size() != 16) {
        throw std::runtime_error("decryptCbcWithIv: malformed input");
    }
    Aes128 aes(EncKeyFor(key));

    std::vector<std::uint8_t> plaintext(in.ciphertext_.size());
    Aes128::Block previous{};
    std::copy(in.iv_or_nonce_.begin(), in.iv_or_nonce_.end(), previous.begin());

    for (std::size_t offset = 0; offset < in.ciphertext_.size(); offset += 16) {
        Aes128::Block block{};
        std::copy(in.ciphertext_.begin() + static_cast<long>(offset), in.ciphertext_.begin() + static_cast<long>(offset) + 16,
                   block.begin());
        Aes128::Block decrypted = aes.DecryptBlock(block);
        XorBlock(plaintext.data() + offset, decrypted.data(), previous.data(), 16);
        previous = block;
    }

    std::uint8_t pad_value = plaintext.back();
    if (pad_value == 0 || pad_value > 16 || pad_value > plaintext.size()) {
        throw std::runtime_error("decryptCbcWithIv: invalid PKCS#7 padding");
    }
    plaintext.resize(plaintext.size() - pad_value);
    return plaintext;
}

CipherResult BlockCipherModes::EncryptCtrWithNonce(const std::vector<std::uint8_t>& plaintext,
                                                    const std::vector<std::uint8_t>& key) {
    Aes128 aes(EncKeyFor(key));
    auto nonce = RandomBytes(8);  // low 8 bytes of the 16-byte counter block

    CipherResult result;
    result.iv_or_nonce_ = nonce;
    result.ciphertext_ = CtrXor(aes, nonce, plaintext);
    return result;
}

std::vector<std::uint8_t> BlockCipherModes::DecryptCtrWithNonce(const CipherResult& in,
                                                                  const std::vector<std::uint8_t>& key) {
    Aes128 aes(EncKeyFor(key));
    return CtrXor(aes, in.iv_or_nonce_, in.ciphertext_);  // CTR decrypt == CTR encrypt
}

CipherResult BlockCipherModes::EncryptGcmStyle(const std::vector<std::uint8_t>& plaintext,
                                                const std::vector<std::uint8_t>& key,
                                                const std::vector<std::uint8_t>& associated_data) {
    Aes128 aes(EncKeyFor(key));
    auto nonce = RandomBytes(8);

    CipherResult result;
    result.iv_or_nonce_ = nonce;
    result.ciphertext_ = CtrXor(aes, nonce, plaintext);

    std::vector<std::uint8_t> mac_input = nonce;
    mac_input.insert(mac_input.end(), associated_data.begin(), associated_data.end());
    mac_input.insert(mac_input.end(), result.ciphertext_.begin(), result.ciphertext_.end());
    auto tag = HmacSha256(MacKeyFor(key), mac_input);
    result.tag_.assign(tag.begin(), tag.end());
    return result;
}

std::vector<std::uint8_t> BlockCipherModes::DecryptGcmStyle(const CipherResult& in,
                                                              const std::vector<std::uint8_t>& key,
                                                              const std::vector<std::uint8_t>& associated_data) {
    std::vector<std::uint8_t> mac_input = in.iv_or_nonce_;
    mac_input.insert(mac_input.end(), associated_data.begin(), associated_data.end());
    mac_input.insert(mac_input.end(), in.ciphertext_.begin(), in.ciphertext_.end());
    auto expected_tag = HmacSha256(MacKeyFor(key), mac_input);

    if (in.tag_.size() != expected_tag.size() ||
        !std::equal(in.tag_.begin(), in.tag_.end(), expected_tag.begin())) {
        throw std::runtime_error("decryptGcmStyle: authentication tag mismatch (tampered ciphertext or wrong key/AAD)");
    }

    Aes128 aes(EncKeyFor(key));
    return CtrXor(aes, in.iv_or_nonce_, in.ciphertext_);
}

}  // namespace cryptotech
