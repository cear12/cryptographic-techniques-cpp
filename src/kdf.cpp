#include "cryptotech/kdf.h"

#include <algorithm>

#include "cryptotech/sha256.h"

namespace cryptotech {

namespace {

std::vector<std::uint8_t> be32(std::uint32_t v) {
    return {static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16),
            static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)};
}

}  // namespace

std::vector<std::uint8_t> pbkdf2HmacSha256(const std::vector<std::uint8_t>& password,
                                            const std::vector<std::uint8_t>& salt, std::uint32_t iterations,
                                            std::size_t derivedKeyLength) {
    constexpr std::size_t kHashLen = Sha256::kDigestSize;
    std::vector<std::uint8_t> derived;
    derived.reserve(derivedKeyLength);

    for (std::uint32_t blockIndex = 1; derived.size() < derivedKeyLength; ++blockIndex) {
        // U1 = HMAC(password, salt || INT_32_BE(blockIndex))
        std::vector<std::uint8_t> u = salt;
        auto indexBytes = be32(blockIndex);
        u.insert(u.end(), indexBytes.begin(), indexBytes.end());
        auto uDigest = hmacSha256(password, u);
        std::vector<std::uint8_t> t(uDigest.begin(), uDigest.end());

        // U2..Uc, XOR-accumulated into T.
        for (std::uint32_t i = 1; i < iterations; ++i) {
            uDigest = hmacSha256(password, std::vector<std::uint8_t>(uDigest.begin(), uDigest.end()));
            for (std::size_t b = 0; b < kHashLen; ++b) t[b] = static_cast<std::uint8_t>(t[b] ^ uDigest[b]);
        }

        std::size_t take = std::min(kHashLen, derivedKeyLength - derived.size());
        derived.insert(derived.end(), t.begin(), t.begin() + static_cast<long>(take));
    }
    return derived;
}

std::vector<std::uint8_t> hkdfSha256(const std::vector<std::uint8_t>& salt, const std::vector<std::uint8_t>& ikm,
                                      const std::vector<std::uint8_t>& info, std::size_t outputLength) {
    constexpr std::size_t kHashLen = Sha256::kDigestSize;

    // Extract: PRK = HMAC(salt, IKM). Per RFC 5869 section 2.2, an empty
    // salt is replaced with a string of kHashLen zero bytes.
    std::vector<std::uint8_t> effectiveSalt = salt.empty() ? std::vector<std::uint8_t>(kHashLen, 0x00) : salt;
    auto prkDigest = hmacSha256(effectiveSalt, ikm);
    std::vector<std::uint8_t> prk(prkDigest.begin(), prkDigest.end());

    // Expand: T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i); OKM = T(1) || T(2) || ...
    std::vector<std::uint8_t> okm;
    std::vector<std::uint8_t> previousT;
    std::uint8_t counter = 1;
    while (okm.size() < outputLength) {
        std::vector<std::uint8_t> input = previousT;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        auto tDigest = hmacSha256(prk, input);
        previousT.assign(tDigest.begin(), tDigest.end());

        std::size_t take = std::min(kHashLen, outputLength - okm.size());
        okm.insert(okm.end(), previousT.begin(), previousT.begin() + static_cast<long>(take));
        ++counter;
    }
    return okm;
}

std::vector<std::uint8_t> memoryHardKdf(const std::vector<std::uint8_t>& password,
                                         const std::vector<std::uint8_t>& salt, std::uint32_t costFactor,
                                         std::size_t derivedKeyLength) {
    // Materialize a costFactor-entry buffer of 32-byte blocks, each derived
    // from the previous one by hashing -- a long, forced-sequential chain
    // that must live in memory in full before the final derivation step can
    // read scattered entries from it. This is the property that makes
    // memory-hard KDFs expensive to parallelize on ASICs/GPUs (limited,
    // fast, per-unit memory), unlike a plain iterated-hash KDF like PBKDF2.
    std::vector<Sha256::Digest> buffer(costFactor);

    std::vector<std::uint8_t> seedInput = password;
    seedInput.insert(seedInput.end(), salt.begin(), salt.end());
    buffer[0] = Sha256::hash(seedInput);
    for (std::uint32_t i = 1; i < costFactor; ++i) {
        buffer[i] = Sha256::hash(std::vector<std::uint8_t>(buffer[i - 1].begin(), buffer[i - 1].end()));
    }

    // Scattered-read mixing pass: fold in pseudorandom-indexed entries from
    // across the whole buffer, so the derivation genuinely depends on all of
    // it having been materialized (not just the last entry).
    Sha256::Digest mixState = buffer.back();
    for (std::uint32_t round = 0; round < 64; ++round) {
        std::uint32_t index = 0;
        for (int b = 0; b < 4; ++b) index = (index << 8) | mixState[static_cast<std::size_t>(b)];
        index %= costFactor;

        std::vector<std::uint8_t> mixInput(mixState.begin(), mixState.end());
        mixInput.insert(mixInput.end(), buffer[index].begin(), buffer[index].end());
        mixState = Sha256::hash(mixInput);
    }

    std::vector<std::uint8_t> finalInput(mixState.begin(), mixState.end());
    finalInput.insert(finalInput.end(), password.begin(), password.end());
    return pbkdf2HmacSha256(finalInput, salt, 1, derivedKeyLength);
}

}  // namespace cryptotech
