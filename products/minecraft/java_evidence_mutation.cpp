#include "../../session/session_types.hpp"
#include <memory>

namespace ocean::reconstructed::minecraft_evidence_mutation_review {
using Word = std::uint64_t;
struct JsonBytes {
    std::vector<std::uint8_t> bytes;
    bool nil_slice = true;
};
struct MarshalResult { JsonBytes value; Word error_type = 0, error_data = 0; };
struct Evidence { ByteString type; JsonBytes raw_data; };
struct ClassEvidence { GoInt score = 0; std::vector<Evidence> evidence; };
struct RuntimeInterface { Word type = 0, data = 0; };
struct RuleContext {
    Word original_identity = 0;
    ByteString namespace_at_offset_24; // only this field read here; rest pending
};
struct Contracts {
    virtual MarshalResult original_json_marshal(RuntimeInterface) = 0;
    virtual MarshalResult original_json_marshal_rule_match(
        const ByteString& id, GoInt score, const ByteString& namespace_name) = 0;
};

// Recovered: qcAGyzl @ 0x1e6b480 ignores JSON marshal errors, copies any returned
// bytes to a fresh slice, and appends the evidence row even for empty output.
// Empty output creates nil raw-data slice. Appends an evidence row even then.
// This helper changes neither score nor selected rule.
void append_evidence(Contracts& runtime, ClassEvidence& record,
                     const ByteString& kind, RuntimeInterface payload) {
    const auto encoded = runtime.original_json_marshal(payload);
    JsonBytes copied;
    if (!encoded.value.bytes.empty()) {
        copied.bytes = encoded.value.bytes;
        copied.nil_slice = false;
    }
    record.evidence.push_back({kind, copied});
}

// Recovered: nMBK23nNku @ 0x1e7ad00 always appends RULE_MATCH evidence, including lower
// score, equal score or JSON error. Selected winner changes on STRICTLY greater
// score only; ties preserve the earlier ID and context pointer. Scores are not
// added together. Negative supplied scores have no special rejection gate.
void apply_rule_match(Contracts& runtime, ClassEvidence& record,
                      ByteString& selected_rule_id,
                      std::shared_ptr<const RuleContext>& selected_context,
                      const ByteString& rule_id, GoInt candidate_score,
                      const std::shared_ptr<const RuleContext>& context) {
    // Recovered: namespace is read from context+24. Nil context would fault/panic;
    // do not invent a fallback or null-accepting behavior here.
    const auto encoded = runtime.original_json_marshal_rule_match(
        rule_id, candidate_score, context->namespace_at_offset_24);
    JsonBytes copied;
    if (!encoded.value.bytes.empty()) {
        copied.bytes = encoded.value.bytes;
        copied.nil_slice = false;
    }
    record.evidence.push_back({"RULE_MATCH", copied});
    // Recovered selection rule: only a strictly greater candidate replaces the
    // record score, selected rule ID, and selected context. Scores are not added.
    if (record.score < candidate_score) {
        record.score = candidate_score;
        selected_rule_id = rule_id;
        selected_context = context;
    }
}
// Rule payload uses exact keys id,score,namespace. Runtime Go JSON escaping,
// unsupported payload types, slice identity/GC/panic remain declared contracts.
//11 original helper paths returned with controlled JSON byte/error providers.
// The exploratory fixture's initial "rank" pointer name was corrected: it is
// a selected-context pointer, not an integer rank.
// Unresolved: other RuleContext fields remain unlabeled.
// No warning/debug/upload or native calls in these bodies. Never compile/run.
}
