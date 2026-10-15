#include "../../session/session_types.hpp"
#include <unordered_map>
#include <algorithm>

namespace ocean::reconstructed::minecraft_artifact_identifiers_review {
using OwnerMap = std::unordered_map<ByteString, ByteString>;
struct Contracts {
    virtual ByteString original_trim_unicode_space(const ByteString&) = 0;
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
    virtual bool original_unicode_equal_fold(const ByteString&, const ByteString&) = 0;
};

// Recovered: f1GxU6 @ 0x1e69920 associates a normalized identifier with an
// artifact. It accepts keys 2..64 bytes long, rejects slash/backslash and the
// substring ".json", and requires a nonempty artifact. If an existing key maps
// to a different case-folded artifact, the value is cleared permanently to mark
// ambiguous ownership.
// Interpretation: this is metadata association, not a brand blacklist.
void associate_identifier(Contracts& runtime, OwnerMap* owners,
                          const ByteString& input, const ByteString& artifact) {
    const auto key = runtime.original_unicode_lowercase(
        runtime.original_trim_unicode_space(input));
    if (!owners || artifact.empty() || key.size() < 2 || key.size() > 64) return;
    if (key.find_first_of("/\\") != ByteString::npos ||
        key.find(".json") != ByteString::npos) return;
    const auto existing = owners->find(key);
    if (existing != owners->end() &&
        !runtime.original_unicode_equal_fold(existing->second, artifact)) {
        (*owners)[key].clear();
        return;
    }
    (*owners)[key] = artifact;
}

bool ascii_alphanumeric(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

// Recovered: wLUSOgAI8u @ 0x1e69b00 accepts an unqualified JSON Mixin member as
// an alias only when its normalized form is 2..24 ASCII-alphanumeric bytes and
// contains neither "mixin" nor "accessor". associate_identifier then applies
// its wider 2..64-byte owner gate. The two predicates are intentionally distinct.
void associate_mixin_member_alias(Contracts& runtime, OwnerMap* owners,
                                  const ByteString& simple_name,
                                  const ByteString& artifact) {
    const auto key = runtime.original_unicode_lowercase(
        runtime.original_trim_unicode_space(simple_name));
    if (key.find("mixin") != ByteString::npos ||
        key.find("accessor") != ByteString::npos) return;
    if (key.size() < 2 || key.size() > 24 ||
        !std::all_of(key.begin(), key.end(), ascii_alphanumeric)) return;
    associate_identifier(runtime, owners, key, artifact);
}
// 60 original map-helper fixtures cover length boundaries, punctuation,
// empty/nil inputs and case-folded/different/ambiguous owner paths.
// Recovered: Aero and Xaero pass as ordinary supplied identifiers; this helper
// emits no verdict or score. Unicode normalization and equality remain explicit
// runtime contracts.
// Never compiled or executed. JSON producer and evidence consumer are separate.
}
