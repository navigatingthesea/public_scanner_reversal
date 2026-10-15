#include "../../session/session_types.hpp"
#include <unordered_set>

namespace ocean::reconstructed::minecraft_sdk_collection_review {
using Word = std::uint64_t;
struct ClassRecord { ByteString name; Word original_record_identity = 0; }; // captured320-byte record
struct Error { Word type = 0, data = 0; bool present() const { return type != 0; } };
struct ClassResult { std::vector<ClassRecord> value; Error error; };
struct Artifacts { Word class_owners = 0, sensitive_categories = 0, identifiers = 0;
                   std::vector<ByteString> paths; };
struct EvidenceSlice { Word data = 0; GoInt length = 0, capacity = 0; }; //152-byte records
struct Result { EvidenceSlice evidence; std::vector<ByteString> unicode_names; Error error; };
struct Rune { std::int32_t value = 0; std::size_t next_byte = 0; };
struct Contracts {
    virtual ClassResult reviewed_pid_class_cache(std::uint32_t) = 0; //Hwp
    virtual Artifacts reviewed_process_artifacts(std::uint32_t) = 0; //jCX, see java_process_artifact_inputs.cpp
    virtual void reviewed_enrich_artifact_categories(
        const std::vector<ClassRecord>&, Word categories,
        Word identifiers) = 0; // eD; see java_mixin_owner_enrichment.cpp
    virtual EvidenceSlice original_full_class_evidence(const std::vector<ClassRecord>&,
                                                       Word class_owners, Word categories) = 0; //g2
    virtual Rune original_decode_utf8(const ByteString&, std::size_t) = 0;
    virtual bool reviewed_excluded_class_name(const ByteString&) = 0; //gOg
};

// Recovered: jVadY0uMPQR @ 0x1e66820 reports each distinct class name containing
// any rune outside printable ASCII (32..126), unless the shared class-name
// exclusion predicate rejects it. Input order is retained. This helper has no
// threshold, score, warning, or artifact gate.
std::vector<ByteString> collect_unicode_class_names(Contracts& runtime,
                                                  const std::vector<ClassRecord>& classes) {
    std::vector<ByteString> result;
    std::unordered_set<ByteString> seen;
    for (const auto& klass : classes) {
        bool outside = false;
        for (std::size_t offset = 0; offset < klass.name.size();) {
            const auto rune = runtime.original_decode_utf8(klass.name, offset);
            if (rune.value < 32 || rune.value > 126) { outside = true; break; }
            offset = rune.next_byte;
        }
        if (!outside || runtime.reviewed_excluded_class_name(klass.name)) continue;
        if (seen.insert(klass.name).second) result.push_back(klass.name);
    }
    return result; // original returns nonnil empty slice, represented by vector
}

// Recovered: eOafqYa @ 0x1e75060. Collection order is fixed: obtain the cached
// class records, obtain process artifacts, enrich artifact categories, build full
// class evidence, and separately collect Unicode class names.
// Raw records are reused through every phase, including an empty success slice.
Result collect_sdk_evidence(Contracts& runtime, std::uint32_t pid) {
    const auto classes = runtime.reviewed_pid_class_cache(pid);
    if (classes.error.present()) return {{}, {}, classes.error};
    // Recovered: artifact collection errors are not returned by this wrapper;
    // the returned artifact structure is passed onward as supplied.
    const auto artifacts = runtime.reviewed_process_artifacts(pid);
    runtime.reviewed_enrich_artifact_categories(classes.value,
        artifacts.sensitive_categories, artifacts.identifiers);
    const auto evidence = runtime.original_full_class_evidence(classes.value,
        artifacts.class_owners, artifacts.sensitive_categories);
    auto unicode = collect_unicode_class_names(runtime, classes.value);
    return {evidence, unicode, {}};
}
// Eight original Unicode-list paths include controls, DEL, non-ASCII, invalid
// UTF8, exclusion, exact byte dedup and original input order. No WARNINGS here.
// Recovered: eOaf discards the artifact path slice itself.
// Unresolved: native collection and the full evidence consumer are contracts in
// this unit and are wired in java_complete_evidence_pipeline.cpp.
// Source review only, never compiled/run; original interpreter is guest-only.
}
