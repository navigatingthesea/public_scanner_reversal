#include "../../session/session_types.hpp"
#include <algorithm>
#include <unordered_map>

namespace ocean::reconstructed::minecraft_class_evidence_review {
struct DecodedRune {
    std::int32_t value = 0;
    std::size_t next_byte = 0;
};

struct Contracts {
    virtual DecodedRune original_decode_utf8(
        const ByteString&,
        std::size_t byte_index) = 0;
    virtual double original_log2(double) = 0; // math.kwtqBT
    virtual bool original_temporary_component(const ByteString&) = 0; // cf_n_TO1Uaq
};

// wbDGT9Ran@1e62b40
double rune_entropy(Contracts& runtime, const ByteString& text) {
    std::unordered_map<std::int32_t, GoInt> frequencies;
    GoInt rune_count = 0;

    for (std::size_t offset = 0; offset < text.size();) {
        const auto decoded = runtime.original_decode_utf8(text, offset);
        ++frequencies[decoded.value];
        ++rune_count;
        offset = decoded.next_byte;
    }

    double entropy = 0;
    for (const auto& [rune, frequency] : frequencies) {
        (void)rune;
        const double probability = double(frequency) / double(rune_count);
        entropy -= probability * runtime.original_log2(probability);
    }
    return entropy;
}

bool numbered_intermediary_class(const ByteString& name) {
    if (name.size() <= 6 || name.compare(0, 6, "class_") != 0) return false;
    for (std::size_t index = 6; index < name.size(); ++index)
        if (name[index] < '0' || name[index] > '9') return false;
    return true;
}

bool ascii_digit(unsigned char value) {
    return value >= '0' && value <= '9';
}

bool ascii_alphanumeric(unsigned char value) {
    return ascii_digit(value) ||
        (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z');
}

// bwmlUDVXsXcd@1e74360
bool obfuscated_identifier(Contracts& runtime, const ByteString& name) {
    if (name.empty() || numbered_intermediary_class(name)) return false;
    if (name.find_first_of("$+/") != ByteString::npos ||
        name.find('[') != ByteString::npos)
        return false;

    // Control characters are immediately considered obfuscated.
    for (std::size_t offset = 0; offset < name.size();) {
        const auto decoded = runtime.original_decode_utf8(name, offset);
        if (decoded.value < 32 || decoded.value == 127) return true;
        offset = decoded.next_byte;
    }

    if (std::all_of(name.begin(), name.end(), ascii_digit)) return false;
    if (!std::all_of(name.begin(), name.end(), ascii_alphanumeric)) return false;
    if (name.size() < 4) return true;

    std::unordered_map<std::int32_t, GoInt> frequencies;
    GoInt largest_frequency = 0;
    for (std::size_t offset = 0; offset < name.size();) {
        const auto decoded = runtime.original_decode_utf8(name, offset);
        largest_frequency =
            std::max(largest_frequency, ++frequencies[decoded.value]);
        offset = decoded.next_byte;
    }

    if (name.size() >= 6 && largest_frequency * 100 / GoInt(name.size()) >= 65)
        return true;
    return name.size() >= 16 && rune_entropy(runtime, name) > 4.25;
}

// Original JSON schema at 0x374f0c0 (56 bytes).
struct Causality {
    ByteString loader_origin = "UNKNOWN";
    ByteString active_caller = "IDLE";
    ByteString caller_file = "UNKNOWN";
    bool is_hook = false;
};
struct Evidence {
    ByteString type;
    std::vector<std::uint8_t> original_json_data;
};

// Original JSON schema at 0x3772f40 (152 bytes). JSON tags provide these
// logical names even though the native field names were obfuscated.
struct ClassEvidence {
    ByteString class_name;
    GoInt score = 0;
    ByteString location;
    bool has_unicode = false;
    Causality causality;
    std::vector<ByteString> flags;
    std::vector<Evidence> evidence;
};

// gdhIEuqJG6l@1e73880
ClassEvidence initial_class_evidence(
    Contracts& runtime,
    const ByteString& class_name,
    const ByteString& location,
    const ByteString& loader_origin) {
    ClassEvidence result;
    result.class_name = class_name;
    result.location = location.empty() ? "UNKNOWN" : location;
    result.causality.loader_origin =
        loader_origin.empty() ? "UNKNOWN" : loader_origin;

    for (std::size_t offset = 0; offset < class_name.size();) {
        const auto decoded = runtime.original_decode_utf8(class_name, offset);
        if (decoded.value < 32 || decoded.value > 126) {
            result.has_unicode = true;
            break;
        }
        offset = decoded.next_byte;
    }

    const auto last_dot = class_name.rfind('.');
    const auto simple_name =
        last_dot == ByteString::npos ? class_name : class_name.substr(last_dot + 1);
    if (obfuscated_identifier(runtime, simple_name)) {
        result.score = 10;
        result.flags.push_back("WEAK:OBFUSCATED_IDENTIFIER");
    }

    // Recovered: test the original location, including an empty string, rather
    // than the display fallback stored above.
    if (runtime.original_temporary_component(location)) {
        result.score = std::max<GoInt>(result.score, 15);
        result.flags.push_back("WEAK:TEMPORARY_CANDIDATE_NAME");
    }
    return result;
}

// Interpretation: the obfuscation predicate recognizes control characters,
// very short ASCII alphanumeric names, repeated-character dominance (>=65%),
// and high rune entropy (>4.25 for at least 16 bytes). Numeric-only names and
// `class_<digits>` intermediary names are explicitly exempt.
//
// Recovered: `has_unicode` means outside printable ASCII 0x20..0x7E, including
// controls, DEL, and decoder RuneError. It is metadata and adds no score. This
// builder always returns a 152-byte record, including at score zero. Later SDK
// aggregation performs admission and final selection. Runtime UTF-8 decoding,
// log2, and map iteration remain contracts. This source was never compiled or
// executed.
}
