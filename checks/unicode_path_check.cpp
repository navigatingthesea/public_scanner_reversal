#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: The path slice whose first word is at original VA 0x14572e1e0 (image RVA
//          0x572e1e0); its three words are RVAs 0x572e1e0/0x572e1e8/0x572e1f0.
//   Gate: Filename checks take priority; otherwise any rune outside U+0020..U+02A0 is disallowed.
//   Output: Appends at most one warning per input path using the recovered display transformation.
//   Failure: The producer and data source of this global remain unresolved and are not inferred
//            here.

namespace ocean::reconstructed::unicode_path_review {

struct Rune {
    std::int32_t value = 0;
};

struct PathContracts {
    virtual ByteString original_windows_basename(const ByteString&) = 0;
    virtual std::vector<Rune> original_go_decode_utf8(const ByteString&) = 0;
    virtual ByteString original_go_rune_string(std::int32_t) = 0;
    virtual void append_warning(const ByteString&) = 0; // RVA 0x572e7a0 -> WARNINGS
};

// Hy8IIwrH5f@12c72a0: original uint32(rune-0x20)<0x281 accepts U+0020
// through U+02A0 inclusive. It rejects control characters, higher Unicode and
// the U+FFFD produced by invalid UTF8. Empty strings pass this predicate.
bool has_disallowed_rune(PathContracts& runtime, const ByteString& text) {
    for (const auto rune : runtime.original_go_decode_utf8(text)) {
        if (static_cast<std::uint32_t>(rune.value - 0x20) >= 0x281) {
            return true;
        }
    }
    return false;
}

// CgxrigTGtKf@12c76c0. Threshold decoded from captured UTF8 U+02A0.
// Runes BELOW U+02A0 are emitted unchanged, even control/NUL. Higher/equal
// runes are surrounded by parentheses via fmt("(%c)"). This is not escaping.
ByteString display(PathContracts& runtime, const ByteString& text) {
    ByteString output;
    for (const auto rune : runtime.original_go_decode_utf8(text)) {
        const auto value = runtime.original_go_rune_string(rune.value);
        output += rune.value < 0x2a0 ? value : "(" + value + ")";
    }
    return output;
}

// Input is the original path slice at VA 0x14572e1e0, corresponding to image
// RVA words 0x572e1e0/0x572e1e8/0x572e1f0. Its producer and data source remain
// unresolved. Warning wording alone is not evidence that every input path
// executed, nor that all files or processes are scanned.
void check_input_paths(PathContracts& runtime,
                       const std::vector<ByteString>& paths) {
    for (const auto& path : paths) {
        const auto filename = runtime.original_windows_basename(path);
        if (has_disallowed_rune(runtime, filename)) {
            runtime.append_warning(
                "File " + display(runtime, filename) +
                " was executed with a Unicode character");
        } else if (has_disallowed_rune(runtime, path)) {
            runtime.append_warning(
                "Path " + display(runtime, path) +
                " contains a Unicode character");
        }
    }
}

// Filename takes priority; at most one warning per input element. Duplicates
// append duplicates here; previously reviewed final WARNINGS normalizer may
// exact-dedup later. Recovery/panic and producer coverage are not proved.

}  // namespace ocean::reconstructed::unicode_path_review
