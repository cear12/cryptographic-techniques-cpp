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
std::vector<std::uint8_t> randomBytes(std::size_t count) {
    std::random_device rd;
    std::vector<std::uint8_t> bytes(count);
    std::generate(bytes.begin(), bytes.end(), [&] { return static_cast<std::uint8_t>(rd()); });
    return bytes;
}

// Reduces an arbitrary-length key to a 16-byte AES-128 key. Domain-separated
// from macKeyFor() below via a trailing tag byte, so the encryption and MAC
// keys used by encryptGcmStyle()/decryptGcmStyle() are independent even
// though they are both derived from the same caller-supplied key material.
Aes128::Key encKeyFor(const std::vector<std::uint8_t>& key) {
    std::vector<std::uint8_t> tagged = key;
    tagged.push_back('E');
    auto digest = Sha256::hash(tagged);
    Aes128::Key aesKey{};
    std::copy(digest.begin(), digest.begin() + static_cast<long>(aesKey.size()), aesKey.begin());
    return aesKey;
}

std::vector<std::uint8_t> macKeyFor(const std::vector<std::uint8_t>& key) {
    std::vector<std::uint8_t> tagged = key;
    tagged.push_back('M');
    auto digest = Sha256::hash(tagged);
    return std::vector<std::uint8_t>(digest.begin(), digest.end());
}

void xorBlock(std::uint8_t* out, const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) out[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
}

// CTR keystream: encrypts nonce||counter for each 16-byte block and XORs it
// with the input. Symmetric -- the same function does both directions.
std::vector<std::uint8_t> ctrXor(const Aes128& aes, const std::vector<std::uint8_t>& nonce,
                                  const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> out(data.size());
    Aes128::Block counterBlock{};
    std::copy(nonce.begin(), nonce.end(), counterBlock.begin());  // nonce occupies the low bytes; upper bytes start at 0

    std::size_t offset = 0;
    std::uint64_t counter = 0;
    while (offset < data.size()) {
        // Store the 64-bit counter in the last 8 bytes of the block, big-endian.
        for (int i = 0; i < 8; ++i) {
            counterBlock[static_cast<std::size_t>(15 - i)] = static_cast<std::uint8_t>(counter >> (8 * i));
        }
        Aes128::Block keystream = aes.encryptBlock(counterBlock);

        std::size_t chunk = std::min<std::size_t>(16, data.size() - offset);
        xorBlock(out.data() + offset, data.data() + offset, keystream.data(), chunk);

        offset += chunk;
        ++counter;
    }
    return out;
}

}  // namespace

CipherResult BlockCipherModes::encryptCbcWithIv(const std::vector<std::uint8_t>& plaintext,
                                                 const std::vector<std::uint8_t>& key) {
    Aes128 aes(encKeyFor(key));

    // PKCS#7 padding up to a multiple of the 16-byte block size.
    std::vector<std::uint8_t> padded = plaintext;
    std::uint8_t padValue = static_cast<std::uint8_t>(16 - (plaintext.size() % 16));
    padded.insert(padded.end(), padValue, padValue);

    auto iv = randomBytes(16);
    CipherResult result;
    result.iv_or_nonce = iv;
    result.ciphertext.resize(padded.size());

    Aes128::Block previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());

    for (std::size_t offset = 0; offset < padded.size(); offset += 16) {
        Aes128::Block block{};
        std::copy(padded.begin() + static_cast<long>(offset), padded.begin() + static_cast<long>(offset) + 16, block.begin());
        xorBlock(block.data(), block.data(), previous.data(), 16);
        Aes128::Block encrypted = aes.encryptBlock(block);
        std::copy(encrypted.begin(), encrypted.end(), result.ciphertext.begin() + static_cast<long>(offset));
        previous = encrypted;
    }
    return result;
}

std::vector<std::uint8_t> BlockCipherModes::decryptCbcWithIv(const CipherResult& in,
                                                               const std::vector<std::uint8_t>& key) {
    if (in.ciphertext.empty() || in.ciphertext.size() % 16 != 0 || in.iv_or_nonce.size() != 16) {
        throw std::runtime_error("decryptCbcWithIv: malformed input");
    }
    Aes128 aes(encKeyFor(key));

    std::vector<std::uint8_t> plaintext(in.ciphertext.size());
    Aes128::Block previous{};
    std::copy(in.iv_or_nonce.begin(), in.iv_or_nonce.end(), previous.begin());

    for (std::size_t offset = 0; offset < in.ciphertext.size(); offset += 16) {
        Aes128::Block block{};
        std::copy(in.ciphertext.begin() + static_cast<long>(offset), in.ciphertext.begin() + static_cast<long>(offset) + 16,
                   block.begin());
        Aes128::Block decrypted = aes.decryptBlock(block);
        xorBlock(plaintext.data() + offset, decrypted.data(), previous.data(), 16);
        previous = block;
    }

    std::uint8_t padValue = plaintext.back();
    if (padValue == 0 || padValue > 16 || padValue > plaintext.size()) {
        throw std::runtime_error("decryptCbcWithIv: invalid PKCS#7 padding");
    }
    plaintext.resize(plaintext.size() - padValue);
    return plaintext;
}

CipherResult BlockCipherModes::encryptCtrWithNonce(const std::vector<std::uint8_t>& plaintext,
                                                    const std::vector<std::uint8_t>& key) {
    Aes128 aes(encKeyFor(key));
    auto nonce = randomBytes(8);  // low 8 bytes of the 16-byte counter block

    CipherResult result;
    result.iv_or_nonce = nonce;
    result.ciphertext = ctrXor(aes, nonce, plaintext);
    return result;
}

std::vector<std::uint8_t> BlockCipherModes::decryptCtrWithNonce(const CipherResult& in,
                                                                  const std::vector<std::uint8_t>& key) {
    Aes128 aes(encKeyFor(key));
    return ctrXor(aes, in.iv_or_nonce, in.ciphertext);  // CTR decrypt == CTR encrypt
}

CipherResult BlockCipherModes::encryptGcmStyle(const std::vector<std::uint8_t>& plaintext,
                                                const std::vector<std::uint8_t>& key,
                                                const std::vector<std::uint8_t>& associatedData) {
    Aes128 aes(encKeyFor(key));
    auto nonce = randomBytes(8);

    CipherResult result;
    result.iv_or_nonce = nonce;
    result.ciphertext = ctrXor(aes, nonce, plaintext);

    std::vector<std::uint8_t> macInput = nonce;
    macInput.insert(macInput.end(), associatedData.begin(), associatedData.end());
    macInput.insert(macInput.end(), result.ciphertext.begin(), result.ciphertext.end());
    auto tag = hmacSha256(macKeyFor(key), macInput);
    result.tag.assign(tag.begin(), tag.end());
    return result;
}

std::vector<std::uint8_t> BlockCipherModes::decryptGcmStyle(const CipherResult& in,
                                                              const std::vector<std::uint8_t>& key,
                                                              const std::vector<std::uint8_t>& associatedData) {
    std::vector<std::uint8_t> macInput = in.iv_or_nonce;
    macInput.insert(macInput.end(), associatedData.begin(), associatedData.end());
    macInput.insert(macInput.end(), in.ciphertext.begin(), in.ciphertext.end());
    auto expectedTag = hmacSha256(macKeyFor(key), macInput);

    if (in.tag.size() != expectedTag.size() ||
        !std::equal(in.tag.begin(), in.tag.end(), expectedTag.begin())) {
        throw std::runtime_error("decryptGcmStyle: authentication tag mismatch (tampered ciphertext or wrong key/AAD)");
    }

    Aes128 aes(encKeyFor(key));
    return ctrXor(aes, in.iv_or_nonce, in.ciphertext);
}

}  // namespace cryptotech
