#include "../../session/session_types.hpp"
#include <cmath>
#include <unordered_map>

namespace ocean::reconstructed::minecraft_hotspot_predicates {
struct Utf8Rune {
    std::int32_t value;
    GoInt next_byte;
};
struct CapturedTextContracts {
    virtual Utf8Rune original_runtime_decode_utf8(const ByteString&, GoInt) = 0;
};

// fuZuFB3V@1e66f00
ByteString class_namespace(const ByteString& class_name) {
    const auto last_dot = class_name.rfind('.');
    return last_dot == ByteString::npos ? ByteString{} : class_name.substr(0, last_dot);
}

// gRQmrNFba@1e6b720
bool contains_control_character(
    CapturedTextContracts& runtime,
    const ByteString& namespace_text) {
    for (GoInt offset = 0; offset < static_cast<GoInt>(namespace_text.size());) {
        const auto first_byte = static_cast<std::uint8_t>(namespace_text[offset]);
        std::int32_t rune = first_byte;
        if (first_byte < 0x80) {
            ++offset;
        } else {
            const auto decoded = runtime.original_runtime_decode_utf8(namespace_text, offset);
            rune = decoded.value;
            offset = decoded.next_byte;
        }
        if (rune < 0x20 || rune == 0x7f) return true;
    }
    return false;
}

// bTn02NbU@1e73840. Field names remain offset based because their producer
// semantics were not recovered with enough confidence to rename them.
struct AggregateEvidenceFields {
    GoInt word48 = 0;
    GoInt word56 = 0;
    GoInt word88 = 0;
    bool map72_present = false;
    GoInt map72_used = 0;
};

bool equal_positive_counts_with_additional_evidence(
    const AggregateEvidenceFields& fields) {
    if (fields.word56 < 1 || fields.word48 != fields.word56) return false;
    if (fields.word88 != 0) return true;
    return fields.map72_present && fields.map72_used > 0;
}

// dUBYTW1@1ea1460
bool ratio_lower_bound_exceeds_half(GoInt successes, GoInt total) {
    if (successes < 20 || total == 0 || successes > total) return false;

    const double sample_size = static_cast<double>(total);
    const double proportion = static_cast<double>(successes) / sample_size;
    constexpr double z = 1.96;
    constexpr double z_squared = 3.8415999999999997;

    const double lower_bound =
        ((z_squared / (sample_size + sample_size) + proportion) -
         std::sqrt(z_squared / (sample_size * 4.0 * sample_size) +
                   ((1.0 - proportion) * proportion) / sample_size) * z) /
        (z_squared / sample_size + 1.0);
    return lower_bound > 0.5;
}

// rZrFxUqCJKvP@1e6b280
bool reason_has_partition_prefix(const ByteString& reason) {
    for (const ByteString prefix : {"WEAK:", "LOADER:", "CRITICAL:"})
        if (reason.compare(0, prefix.size(), prefix) == 0) return true;
    return false;
}

struct ReasonPartition {
    std::vector<ByteString> prefixed;
    std::vector<ByteString> other;
};

// fzW5ul@1e6aa00
ReasonPartition partition_reasons(const std::vector<ByteString>& input) {
    ReasonPartition result;
    for (const auto& reason : input) {
        auto& destination =
            reason_has_partition_prefix(reason) ? result.prefixed : result.other;
        destination.push_back(reason);
    }
    return result;
}

// wHxvKHz9@1e6e3a0
ByteString lookup_full_or_simple_name(
    const std::unordered_map<ByteString, ByteString>* values,
    const ByteString& name) {
    if (values == nullptr || name.empty()) return {};

    auto found = values->find(name);
    if (found != values->end() && !found->second.empty()) return found->second;

    const auto last_dot = name.rfind('.');
    if (last_dot != ByteString::npos && last_dot + 1 < name.size()) {
        found = values->find(name.substr(last_dot + 1));
        if (found != values->end() && !found->second.empty()) return found->second;
    }
    return {};
}

// Recovered check meanings:
// - class_namespace returns bytes before the last literal dot; slash is ignored.
// - contains_control_character flags C0 controls and DEL, not non-ASCII text.
// - equal_positive_counts_with_additional_evidence requires equal positive
//   counts plus either word88 or a nonempty map at +72.
// - ratio_lower_bound_exceeds_half requires at least 20 successes, then compares
//   a Wilson-style 95% lower bound strictly with 0.5.
// - partition_reasons preserves order and duplicates.
// - lookup_full_or_simple_name tries the exact key before the last-dot suffix.
//
// Unresolved: the producer meanings of aggregate offsets +48, +56, +72, and
// +88 are not proven, so names such as "injected classes" would overstate the
// evidence. These helpers emit no verdict on their own. This readable source
// was never compiled or executed.
}
