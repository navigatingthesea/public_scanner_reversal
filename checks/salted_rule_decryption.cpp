#include "../session/session_types.hpp"
#include <array>
#include <optional>
// Recovered behavior summary:
//   Input: Standard-base64 OpenSSL Salted__ material and a password.
//   Gate: Requires header, block-aligned ciphertext, AES-256-CBC setup, and valid PKCS#7 padding
//         after MD5-chain key derivation.
//   Output: Returns the unpadded plaintext, preserving nonnil empty plaintext for a full padding
//           block.
//   Failure: Decode/header/length/cipher/padding failures return nullopt; authentication is absent.

namespace ocean::reconstructed::salted_rule_decryption {

struct CryptoContracts {
    virtual std::optional<ByteString> base64_standard_decode(
        const ByteString&) = 0;
    virtual ByteString md5_binary_16(const ByteString&) = 0;
    virtual bool aes_256_new_cipher(const ByteString& key) = 0;
    virtual ByteString aes_cbc_decrypt_blocks(
        const ByteString& key,
        const ByteString& iv,
        const ByteString& ciphertext) = 0;
};

struct KeyIv {
    ByteString key;
    ByteString iv;
};

KeyIv derive(CryptoContracts& runtime,
             const ByteString& password,
             const ByteString& salt) { // urinUbb @ 0xe36fe0
    ByteString material;
    ByteString previous_digest;
    while (material.size() < 48) {
        previous_digest = runtime.md5_binary_16(
            previous_digest + password + salt);
        material += previous_digest;
    }
    return {material.substr(0, 32), material.substr(32, 16)};
}

std::optional<ByteString> decrypt(
    CryptoContracts& runtime,
    const ByteString& encoded,
    const ByteString& password) { // G_a_Qna @ 0xe36be0
    const auto decoded = runtime.base64_standard_decode(encoded);
    if (!decoded || decoded->size() <= 15) {
        return std::nullopt;
    }
    if (decoded->compare(0, 8, "Salted__") != 0) {
        return std::nullopt;
    }

    const auto ciphertext_length = decoded->size() - 16;
    if (ciphertext_length == 0 || (ciphertext_length & 15) != 0) {
        return std::nullopt;
    }

    const auto key_iv = derive(runtime, password, decoded->substr(8, 8));
    if (!runtime.aes_256_new_cipher(key_iv.key)) {
        return std::nullopt;
    }
    auto plaintext = runtime.aes_cbc_decrypt_blocks(
        key_iv.key, key_iv.iv, decoded->substr(16));

    const auto padding = static_cast<unsigned char>(plaintext.back());
    if (padding == 0 || padding > 16 || plaintext.size() < padding) {
        return std::nullopt;
    }
    for (auto index = plaintext.size() - padding;
         index < plaintext.size(); ++index) {
        if (static_cast<unsigned char>(plaintext[index]) != padding) {
            return std::nullopt;
        }
    }
    plaintext.resize(plaintext.size() - padding);
    return plaintext;
    // Valid full-block padding returns a nonnull empty slice. Optional models
    // that distinction; every error path returns nullopt.
}

// The original header, 48-byte MD5 chain, CBC invocation, and PKCS#7 byte
// validation are represented here. MD5 and AES internals remain library
// contracts. There is no PBKDF2, iteration multiplier, authentication tag, or
// MAC in this helper.

}  // namespace ocean::reconstructed::salted_rule_decryption
