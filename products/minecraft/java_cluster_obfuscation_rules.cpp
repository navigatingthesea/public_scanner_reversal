#include "../../session/session_types.hpp"
#include <cmath>
namespace ocean::reconstructed::minecraft_cluster_obfuscation_rules_review {
using Word=std::uint64_t;
struct Error {Word type=0,data=0;};
struct StatResult {Error error;}; // FileInfo returned by Stat is unused here
struct ArtifactFlags {bool temporary_name=false,missing_at_scan=false;};
struct Cluster {
    ByteString indexed_artifact,namespace_name;
    GoInt distinct_classes=0;        // len(class-name set at context+40)
    GoInt obfuscated_names=0;        // context+48, within this artifact bucket
    GoInt namespace_classes=0;       // context+56, spans artifacts in same loader
    bool obfuscated_majority=false;  // context+64: reviewed Wilson predicate
    ArtifactFlags artifact_flags;    // context+65/+66
};
struct Contracts {
    virtual bool original_temporary_component(const ByteString&)=0; // cf, reviewed
    virtual bool original_windows_is_absolute(const ByteString&)=0; // CR61/XD2
    virtual StatResult original_stat(const ByteString&)=0; // real I/O contract
    virtual bool original_is_not_exist(Error)=0; // H3/nXSO, target ErrNotExist
};
struct RuleSink {
    virtual void apply_rule_match(const ByteString& id,GoInt score,const Cluster&)=0;
};

// Context initialization: temporary flag always computed from artifact string.
// Stat only for an absolute Windows path. Relative/missing paths are not probed
// by this body. Stat error is classified with IsNotExist; other errors are false.
ArtifactFlags collect_artifact_flags(Contracts& runtime,const ByteString& artifact) {
    ArtifactFlags flags;
    flags.temporary_name=runtime.original_temporary_component(artifact);
    if(runtime.original_windows_is_absolute(artifact))
        flags.missing_at_scan=runtime.original_is_not_exist(runtime.original_stat(artifact).error);
    return flags;
}

// Recovered: dUB @ 0x1ea1460 writes this predicate to context+64. It is an
// obfuscation-majority confidence flag, not a "native backing" flag.
// Uses artifact-bucket obfuscated successes / loader+namespace-wide total.
// The separately reviewed original helper has69 boundary paths. Counters are
// Go signed64 values, but normal map-derived inputs are nonnegative.
bool obfuscated_majority_with_confidence(GoInt successes,GoInt total) {
    if(successes<20 || total==0 || successes>total) return false;
    constexpr double z=1.96,z2=z*z;
    const double n=static_cast<double>(total),p=static_cast<double>(successes)/n;
    const double lower=(p+z2/(2*n)-z*std::sqrt((p*(1-p)+z2/(4*n))/n))/(1+z2/n);
    return lower>0.5;
}
void finish_cluster_confidence(Cluster& cluster) {
    cluster.obfuscated_majority=obfuscated_majority_with_confidence(
        cluster.obfuscated_names,cluster.namespace_classes);
}
bool artifact_is_unbacked_or_temporary(const Cluster& cluster) {
    return cluster.indexed_artifact.empty() || cluster.artifact_flags.temporary_name ||
           cluster.artifact_flags.missing_at_scan;
}

// gRQ@1e6b720 reads context namespace words24/32 and looks for rune<32
//or DEL127. Byte scan is equivalent for these ASCII control values in UTF8,
//including invalid sequences (RuneError itself is not a matching control).
bool namespace_has_control_identifier(const ByteString& value) {
    for(const unsigned char byte:value) if(byte<32 || byte==127) return true;
    return false;
}

// Recovered: the caller applies these rules to every eligible class in the same bucket.
// nMB always appends match evidence and changes winner only on STRICTLY higher
// score. Thus both80 and82 remain in RULE_MATCH evidence, winner82 when both fire.
// No score sum, warning or immediate upload in these branches.
void apply_obfuscation_rules(RuleSink& output,const Cluster& cluster) {
    const bool eligible_artifact=artifact_is_unbacked_or_temporary(cluster);
    // Recovered @ 0x1e86f79, g2.func78: confidence + unbacked artifact + a
    // control byte in the namespace emits CLUSTER_UNBACKED_CONTROL_IDENTIFIERS
    // (85). There is no 100-class gate here:
    // the confidence helper itself supplies the minimum20-successes gate.
    if(cluster.obfuscated_majority && eligible_artifact &&
       namespace_has_control_identifier(cluster.namespace_name))
        output.apply_rule_match("CLUSTER_UNBACKED_CONTROL_IDENTIFIERS",85,cluster);

    // Recovered @ 0x1e86d97, g2.func43: confidence + unbacked artifact + at
    // least 100 distinct class names emits UNBACKED_MASSIVE_OBFUSCATED_CLUSTER
    // (80).
    if(cluster.obfuscated_majority && eligible_artifact && cluster.distinct_classes>=100)
        output.apply_rule_match("UNBACKED_MASSIVE_OBFUSCATED_CLUSTER",80,cluster);

    // Recovered @ 0x1e95c8a: this separate rule does not test context+64.
    // Requires ALL bucket names obfuscated, at least100 distinct names and
    // namespace byte length<4. It does not count UTF8 runes or namespace parts.
    if(eligible_artifact && cluster.distinct_classes==cluster.obfuscated_names &&
       cluster.distinct_classes>=100 && cluster.namespace_name.size()<4)
        output.apply_rule_match("SHORT_NAMESPACE_MASSIVE_OBFUSCATION",82,cluster);
}
//12 full SDK original fixtures returned with declared native/JSON/map providers:
//99reject/100accept;3-byte namespace82/4-byte namespace80; one ordinary name
//prevents82but retains80; duplicates reducing distinct count99reject;59/100
//confidence rejects80 while60/100passes; existing absolute/relative artifact
//rejects both; temporary or captured ErrNotExist artifact allows them.
//An initial base provider shadow forced the OS predicate false; both nil-only
//and parent fallback interceptors removed, original H3/nXSO compared captured
//ErrNotExist successfully; artifact matrix rerun before generating this file.
//Raw metadata keys such as ratio_lower_bound can be misleading; flags/counts
//above are from original producer instructions and independently typed schema.
//Runtime Stat/IsNotExist, native record production, serializer and other SDK
// rules are mapped in adjacent units and wired by
// java_complete_evidence_pipeline.cpp. Never compile/run this source.
}

//Five additional full SDK fixtures:20obfuscated names with namespace control
//31/127/tab trigger85, ordinary/nonASCII128 do not. All original returns.
//Helper address correction dUB@1ea1460 supersedes an erroneous nearby RVA label.
