#include "../../session/session_types.hpp"

namespace ocean::reconstructed::minecraft_unicode_method_review {
struct RuneStep {
    std::int32_t value;
    GoInt next_byte;
};
struct ClassStrings {
    ByteString class_name;
    std::vector<ByteString> member_names;
};
struct UnicodeMethodContracts {
    virtual ByteString original_unicode_to_lower(const ByteString&) = 0;
    virtual RuneStep original_runtime_utf8_decoder(const ByteString&, GoInt byte_offset) = 0;
    virtual void append_debug_with_signed_count(
        const ByteString& level,
        const ByteString& label,
        const ByteString& class_name,
        GoInt total_classes) = 0;
    virtual void original_detection_diagnostic(const ByteString&) = 0;
};

// wY88WdQN@1c08aa0
bool excluded_class_name(
    UnicodeMethodContracts& runtime,
    const ByteString& class_name) {
    const auto lower = runtime.original_unicode_to_lower(class_name);
    for (const ByteString fragment : {
             "i18n", "fi.dy.masa", "gg.norisk", "com.moulberry"})
        if (lower.find(fragment) != ByteString::npos) return true;
    return false;
}

bool has_ten_consecutive_unusual_runes(
    UnicodeMethodContracts& runtime,
    const ByteString& member_name) {
    unsigned consecutive = 0;
    for (GoInt offset = 0; offset < static_cast<GoInt>(member_name.size());) {
        const auto first_byte = static_cast<std::uint8_t>(member_name[offset]);
        std::int32_t rune = first_byte;
        if (first_byte < 0x80) {
            ++offset;
        } else {
            const auto decoded = runtime.original_runtime_utf8_decoder(member_name, offset);
            rune = decoded.value;
            offset = decoded.next_byte;
        }

        if (rune < 0x20 || rune > 0x2a0) {
            if (++consecutive >= 10) return true;
        } else {
            consecutive = 0;
        }
    }
    return false;
}

// bcxqXhF90K@1c09140
void check_supplied_class_member_names(
    UnicodeMethodContracts& runtime,
    const std::vector<ClassStrings>& classes) {
    std::vector<ByteString> flagged_classes;

    for (const auto& row : classes) {
        if (excluded_class_name(runtime, row.class_name)) continue;

        for (const auto& member_name : row.member_names) {
            if (!has_ten_consecutive_unusual_runes(runtime, member_name)) continue;
            flagged_classes.push_back(row.class_name);
            break; // At most one count per class, regardless of matching methods.
        }
    }

    if (flagged_classes.size() < 10) return;

    const auto total = static_cast<GoInt>(flagged_classes.size());
    for (const auto& class_name : flagged_classes) {
        runtime.append_debug_with_signed_count(
            "Detect", "Game Unicode String", class_name, total);
    }
    runtime.original_detection_diagnostic("Generic Cheat T:::In instance [R]");
}

// Recovered check:
// 1. Ignore classes whose lowercased name contains one of four exact fragments.
// 2. Flag a class when any member name has ten consecutive runes below U+0020
//    or above U+02A0.
// 3. Emit debug records only when at least ten distinct map rows/classes qualify.
//
// DEL (U+007F) is allowed here. Malformed UTF-8 is handled by Go's decoder, so
// repeated RuneError values can satisfy the high-rune condition. The input is a
// Go map[string][]string; order is unspecified, and this vector represents one
// possible original iteration order. This helper appends DEBUG_DETECTIONS and a
// diagnostic, but no WARNINGS entry. The diagnostic callee's side effects remain
// unresolved. This readable reconstruction was never compiled or executed.
}
