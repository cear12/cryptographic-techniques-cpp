#include "cryptotech/substitution_cipher.h"

#include <algorithm>
#include <random>

namespace educational_crypto {

SubstitutionCipher::Key SubstitutionCipher::generate_key() {
    Key key{};
    for (int i = 0; i < 26; ++i) key[static_cast<std::size_t>(i)] = static_cast<char>('A' + i);

    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(key.begin(), key.end(), rng);
    return key;
}

std::string SubstitutionCipher::encrypt(const std::string& plaintext, const Key& key) {
    std::string out = plaintext;
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = key[static_cast<std::size_t>(c - 'A')];
    }
    return out;
}

std::string SubstitutionCipher::decrypt(const std::string& ciphertext, const Key& key) {
    Key inverse{};
    for (int i = 0; i < 26; ++i) {
        inverse[static_cast<std::size_t>(key[static_cast<std::size_t>(i)] - 'A')] = static_cast<char>('A' + i);
    }
    return encrypt(ciphertext, inverse);
}

}  // namespace educational_crypto
