#include "../../session/session_types.hpp"
#include <algorithm>
#include <set>
#include <vector>

namespace ocean::reconstructed::minecraft_fallback_method_owner {
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
};

std::vector<ByteString> split_on_dollar(const ByteString& value) {
    std::vector<ByteString> parts;
    std::size_t begin = 0;
    for (;;) {
        const auto next = value.find('$', begin);
        if (next == ByteString::npos) {
            parts.push_back(value.substr(begin));
            return parts;
        }
        parts.push_back(value.substr(begin, next - begin));
        begin = next + 1;
    }
}

// d8JTBjsNNQ@1e71700..1e73840
ByteString fallback_owner(Contracts& runtime, const ByteString& method_name) {
    const auto parts = split_on_dollar(
        runtime.original_unicode_lowercase(method_name));
    if (parts.size() < 4) return {};

    static const std::set<ByteString> accepted_prefixes = {
        "handler", "redirect", "modifyarg", "modifyargs", "modifyvariable",
        "modifyconstant", "modifyexpressionvalue", "modifyreturnvalue",
        "wrapoperation", "wrapwithcondition", "localvar", "args",
    };
    if (accepted_prefixes.find(parts[0]) == accepted_prefixes.end()) return {};

    auto owner = parts[3];
    owner.erase(
        std::remove_if(owner.begin(), owner.end(), [](unsigned char byte) {
            return byte == '-' || byte == '_';
        }),
        owner.end());
    if (owner.empty()) return {};

    for (const unsigned char byte : owner) {
        const bool ascii_alphanumeric =
            (byte >= 'a' && byte <= 'z') ||
            (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9');
        if (!ascii_alphanumeric) return {};
    }
    return owner;
}

// Interpretation: when the primary mixin-method parser yields an owner ID but
// same-loader lookup for that ID is empty, this fallback treats the fourth `$`
// component as an alternate owner key. Hyphens and underscores are removed.
// There is no first-letter or length rule, so one character, all digits, and a
// 256-character component all pass.
//
// Recovered example: `handler$nonce$abc$attackpacket` can look in the
// `abc.attackpacket.client` bucket using `attackpacket`, while namespace-prefix
// ambiguity is still evaluated against the original primary ID `abc`. The q.
// namespace fails because it contains no `abc` component. Forty-nine original
// paths were checked. Unicode lowercasing remains a provider contract. This
// readable reconstruction was never compiled or executed.
}
