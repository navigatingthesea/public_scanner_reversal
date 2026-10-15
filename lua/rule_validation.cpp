#include "captured_lua_environment.hpp"
#include <algorithm>
#include <optional>

namespace ocean::reconstructed::lua_review {
// aUshQ9KbD.e3yAnkh_su1@0x1f0aba0
std::optional<ByteString> validate_rule_payload_for_review(
    const std::vector<std::uint8_t>& bytes) {
    constexpr std::array<std::uint8_t, 4> bytecode_signature = {
        0x1b, 'L', 'u', 'a',
    };
    if (bytes.size() >= bytecode_signature.size() &&
        std::equal(bytecode_signature.begin(), bytecode_signature.end(), bytes.begin()))
        return ByteString("precompiled bytecode refused");

    constexpr std::array<std::uint8_t, 12> forbidden_name = {
        'c', 'a', 'e', 's', 'a', 'r', 'E', 'n', 'c', 'o', 'd', 'e',
    };
    if (std::search(bytes.begin(), bytes.end(),
                    forbidden_name.begin(), forbidden_name.end()) != bytes.end())
        return ByteString("script refused");
    return std::nullopt;
}

// Input is the raw rule payload. The exact `\x1bLua` prefix and a case-sensitive
// `caesarEncode` byte substring are rejected in that order. Output is nil on
// acceptance or the captured error text on refusal. This byte filter does not
// parse Lua and does not establish a general interpreter security boundary.
}
