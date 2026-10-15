#include "../../session/session_types.hpp"
#include <algorithm>
#include <array>
#include <vector>
namespace ocean::reconstructed::minecraft_java_bytecode_snapshot {
using Bytes = std::vector<std::uint8_t>;

struct Contracts {
    virtual std::array<std::uint8_t, 32> original_sha256(const Bytes&) = 0;
};
struct Snapshot {
    Bytes prefix;
    ByteString digest_hex;
    bool truncated;
};

Snapshot capture(Contracts& runtime, const Bytes& bytecode) { // xWa@1a4b480
    // Recovered: hash the complete method body before limiting the stored copy.
    // Jp3vzhB.GIoGJR@75b580 calls Go's FIPS SHA-256 Reset/Write/Sum path.
    const auto digest = runtime.original_sha256(bytecode);
    const auto copied = std::min(bytecode.size(), std::size_t{4096});
    Snapshot result{
        {bytecode.begin(), bytecode.begin() + copied},
        {},
        bytecode.size() != copied,
    };

    static constexpr char hex[] = "0123456789abcdef";
    for (const auto byte : digest) {
        result.digest_hex += hex[byte >> 4];
        result.digest_hex += hex[byte & 15];
    }
    return result;
}
// Recovered: the 296-byte method record stores the prefix at +144, its digest
// string at +176, and the truncation flag at +192. The original uint16 code
// length is stored separately at +168. Cases around the 4096-byte boundary
// confirmed that the digest always covers the full body and is 64 lowercase
// hexadecimal characters. This readable reconstruction was never compiled or
// executed.
}
