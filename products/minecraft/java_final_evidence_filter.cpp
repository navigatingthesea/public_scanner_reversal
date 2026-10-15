#include "../../session/session_types.hpp"
#include <unordered_map>
#include <algorithm>

namespace ocean::reconstructed::minecraft_final_evidence_review {
struct JsonBytes { std::vector<std::uint8_t> value; bool nil_slice = true; };
struct Evidence { ByteString type; JsonBytes raw_data; };
struct ClassEvidence {
    ByteString class_name;
    GoInt score = 0;
    ByteString location;
    bool has_unicode = false;
    ByteString loader_origin, active_caller, caller_file;
    bool is_hook = false;
    std::vector<ByteString> flags;
    std::vector<Evidence> evidence;
};
struct MarshalResult { JsonBytes value; std::uint64_t error_type = 0, error_data = 0; };
struct Contracts {
    virtual void original_go_sort_in_place(std::vector<ClassEvidence>&,
        bool (*less)(const ClassEvidence&, const ClassEvidence&)) = 0;
    virtual MarshalResult original_summary_json(GoInt equivalent_detections,
                                               GoInt representatives) = 0;
};

// Recovered: xlB...func5 @ 0x1e9d8e0 sorts by signed score descending,
// class-name bytes ascending, then loader-origin bytes ascending.
// bytes ASC. Original comparator bounds-panic on either invalid index.
bool record_less(const ClassEvidence& left, const ClassEvidence& right) {
    if (left.score != right.score) return left.score > right.score;
    if (left.class_name != right.class_name) return left.class_name < right.class_name;
    return left.loader_origin < right.loader_origin;
}

// Recovered: s9ruoG @ 0x1e6bac0 uses only the case-sensitive evidence types RULE,
// CLUSTER, and ARTIFACT, preserving their existing order.
// Concatenate type + ':' + RAW JSON BYTES, with no separator between entries.
// No JSON parsing, canonicalization, whitespace trim, sorting or dedup.
ByteString equivalence_key(const ClassEvidence& record) {
    ByteString key;
    for (const auto& evidence : record.evidence) {
        if (evidence.type != "RULE" && evidence.type != "CLUSTER" &&
            evidence.type != "ARTIFACT") continue;
        key += evidence.type;
        key += ':';
        for (const auto byte : evidence.raw_data.value) key += static_cast<char>(byte);
    }
    return key;
}

// Recovered: xlBHSXCz @ 0x1e9c8c0 sorts 152-byte input records in place. It keeps
// at most three records per equivalence key and appends SUMMARY JSON to each kept
// copy. It does not apply a score threshold.
// their fields and adds SUMMARY to each chosen copy. No score threshold here.
std::vector<ClassEvidence> select_representatives(Contracts& runtime,
                                                std::vector<ClassEvidence>& inputs) {
    runtime.original_go_sort_in_place(inputs, record_less);
    std::unordered_map<ByteString, GoInt> totals;
    for (const auto& record : inputs) ++totals[equivalence_key(record)];
    std::unordered_map<ByteString, GoInt> selected;
    std::vector<ClassEvidence> result;
    for (const auto& original : inputs) {
        const auto key = equivalence_key(original);
        if (selected[key] >= 3) continue;
        ++selected[key];
        const auto encoded = runtime.original_summary_json(totals[key],
                                                           std::min<GoInt>(totals[key], 3));
        ClassEvidence copy = original;
        JsonBytes bytes;
        if (!encoded.value.value.empty()) {
            bytes.value = encoded.value.value;
            bytes.nil_slice = false;
        }
        // Recovered: marshal errors are ignored; empty/error output still appends
        // SUMMARY with a nil byte slice.
        // Exact JSON keys equivalent_detections and representatives.
        copy.evidence.push_back({"SUMMARY", bytes});
        result.push_back(copy);
    }
    return result; // original nonnil empty result when inputs empty
}
// Unresolved: Go sorting does not promise stability for identical three-field keys.
// Fixture sort provider follows verified comparator; equal-key stability is
// unproved. Original record-copy slice sharing/backing-array/GC/panic semantics
// are runtime contracts; C++ vectors express logical retained values only.
//15 baseline +10 default-group +4distinct-group +14key paths returned;
//9 comparator paths returned and2 original bounds-panic stops.
// All records without recognized evidence share the EMPTY key, irrespective
// of class/location/loader. Class duplicates are not removed by this helper.
// Recovered elsewhere: g2 rule admission and the signed score > 69 gate are
// wired in java_complete_evidence_pipeline.cpp.
// Never compile/run this review source. No native/sample execution.
}
