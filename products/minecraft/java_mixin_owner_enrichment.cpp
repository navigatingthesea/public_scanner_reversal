#include "../../session/session_types.hpp"
#include <array>
#include <string_view>
#include <algorithm>
#include <unordered_map>

namespace ocean::reconstructed::minecraft_mixin_owner_review {
using OwnerMap = std::unordered_map<ByteString, ByteString>;
using CategorySet = std::unordered_map<ByteString, bool>;
using ArtifactFeatures = std::unordered_map<ByteString, CategorySet>;
struct NestedRecord296 { ByteString raw_string_at_0; }; // record size296 verified
struct RawClass320 {
    ByteString name;
    std::vector<NestedRecord296> raw_slice_at_128;
    bool raw_flag_at_224 = false; // bootstrap-class marker from loader graph; dictionary mode is false
};
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
    virtual std::vector<ByteString> reviewed_sensitive_categories(const ByteString&) = 0;
};

std::vector<ByteString> split_preserving_empty(const ByteString& text, char separator) {
    std::vector<ByteString> result;
    std::size_t start = 0;
    while (true) {
        const auto end = text.find(separator, start);
        if (end == ByteString::npos) { result.push_back(text.substr(start)); return result; }
        result.push_back(text.substr(start, end - start));
        start = end + 1;
    }
}
bool ascii_alphanumeric(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

// Recovered: kDR19No @ 0x1e6e800 parses a lowercased Mixin-generated method name.
// At least4 dollar-separated components; second and fourth must be nonempty.
// Extra components are ignored. Return third component WITH its _/- retained.
ByteString method_owner_identifier(Contracts& runtime, const ByteString& method_name) {
    const auto parts = split_preserving_empty(runtime.original_unicode_lowercase(method_name), '$');
    if (parts.size() < 4 || parts[1].empty() || parts[3].empty()) return {};
    constexpr std::array<std::string_view, 12> accepted = {
        "handler", "redirect", "modifyarg", "modifyargs", "modifyvariable",
        "modifyconstant", "modifyexpressionvalue", "modifyreturnvalue",
        "wrapoperation", "wrapwithcondition", "localvar", "args"
    };
    if (std::find(accepted.begin(), accepted.end(), parts[0]) == accepted.end()) return {};
    ByteString validation;
    for (const char byte : parts[2])
        if (byte != '_' && byte != '-') validation.push_back(byte);
    if (validation.empty() ||
        !std::all_of(validation.begin(), validation.end(), ascii_alphanumeric)) return {};
    return parts[2];
}

// Recovered: wHxvKHz9 @ 0x1e6e3a0 first resolves the exact full key. A missing
// or empty full-key value still permits a last-dot simple-name fallback.
ByteString resolve_owner(const OwnerMap& map, const ByteString& name) {
    const auto full = map.find(name);
    if (full != map.end() && !full->second.empty()) return full->second;
    const auto dot = name.rfind('.');
    if (dot == ByteString::npos) return {};
    const auto simple = map.find(name.substr(dot + 1));
    return simple == map.end() ? ByteString{} : simple->second;
}

// Recovered: d7baAC96wbdH @ 0x1e6e300 applies the sensitive-category matcher to
// any target class simple name; it has no Mixin/accessor marker gate.
// This differs from cGxA94's gate for names discovered as ZIP class entries.
std::vector<ByteString> target_class_categories(Contracts& runtime, const ByteString& name) {
    const auto dot = name.rfind('.');
    return runtime.reviewed_sensitive_categories(
        dot == ByteString::npos ? name : name.substr(dot + 1));
}

// Recovered: eD1AWD37DdV @ 0x1e6e4c0 attaches target-class categories to the
// artifact resolved from each Mixin-generated nested method's owner identifier.
// Synthetic fixtures prove the320/296-byte strides and offsets. Do not rename
// raw_flag224 is the bootstrap marker; the nested method record is produced by the method collector.
void enrich_artifact_categories(Contracts& runtime,
                                const std::vector<RawClass320>& classes,
                                ArtifactFeatures* features, const OwnerMap* identifiers) {
    if (!features || !identifiers || identifiers->empty()) return;
    for (const auto& klass : classes) {
        if (klass.raw_flag_at_224) continue;
        const auto categories = target_class_categories(runtime, klass.name);
        if (categories.empty()) continue;
        for (const auto& nested : klass.raw_slice_at_128) {
            const auto owner = method_owner_identifier(runtime, nested.raw_string_at_0);
            if (owner.empty()) continue;
            const auto artifact = resolve_owner(*identifiers, owner);
            if (artifact.empty()) continue;
            auto& destination = (*features)[artifact];
            for (const auto& category : categories) destination[category] = true;
        }
    }
}
// 78 original parser paths matched the readable model;16 enrichment paths
// returned with category/parser providers and the original owner lookup body.
// Interpretation: names including aero/xaero are ordinary supplied owner IDs,
// not a verdict or a dedicated branded check.
// Recovered: these helpers emit no score, debug row, warning, or report. The 21
// g2 rules are wired in java_complete_evidence_pipeline.cpp.
// Runtime Unicode behavior stays explicit. Source never compiled or executed.
}
