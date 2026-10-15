#include "../../session/session_types.hpp"
#include <map>
#include <vector>
namespace ocean::reconstructed::minecraft_secondary_artifact_rules {
using Domains=std::map<ByteString,bool>;
struct Artifact {
    std::int64_t obfuscated_count_at_0=0;
    bool any_unbacked_at_9=false;
    Domains correlated_domains_at_24;
    std::int64_t class_count_at_32=0;
};
struct Cluster {
    ByteString artifact,namespace_name;
    bool confidence_at_64=false;
    std::int64_t distinct_names=0;
};
using Profiles=std::map<ByteString,Artifact>;
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
    virtual bool reviewed_exact_mods_component(const ByteString&)=0;
    virtual bool reviewed_candidate_in_known_path(const ByteString&,const Artifact*)=0;
    virtual bool reviewed_secondary_domains(const Domains&)=0;
    virtual bool reviewed_dense_domains(const Domains&)=0;
    virtual void append_original_rule_match(const ByteString&,std::int64_t,
                                             const ByteString&)=0;
};
struct Selection {ByteString artifact;std::int64_t best_count=-1;};
void consider(Selection& selected,const Profiles& profiles,const ByteString& candidate) {
    const auto found=profiles.find(candidate);if(found==profiles.end()) return;
    // Recovered: func2.func120 ranks only obfuscated_count_at_0. Equal counts
    // keep the first artifact encountered in Go map iteration order.
    if(found->second.obfuscated_count_at_0>selected.best_count) {
        selected.best_count=found->second.obfuscated_count_at_0;
        selected.artifact=candidate;
    }
}
Selection select_primary(Contracts& runtime,const Profiles& profiles,
    const std::vector<ByteString>& first_go_map_iteration,
    const std::vector<ByteString>& fallback_go_map_iteration) {
    Selection selected;
    for(const auto& candidate:first_go_map_iteration)
        if(!runtime.reviewed_exact_mods_component(candidate))
            consider(selected,profiles,candidate);
    if(selected.best_count<0)
        for(const auto& candidate:fallback_go_map_iteration)
            consider(selected,profiles,candidate);
    return selected;
}
// Recovered: Go map iteration is not sorted here. Equal counts retain the first encountered
// key, and the fallback performs a fresh map enumeration. Do not invent a
// lexical tie-break. Empty artifact keys can be selected. This is a count-based
// selected artifact, not a proof that it is the actual launcher/main/game JAR.
bool secondary_sensitive(Contracts& runtime,const Profiles& profiles,
                          const Selection& selected,const ByteString& candidate) {
    // Recovered gates: nonempty and not the selected primary artifact; profile
    // exists; path is not recognized as a known client/mods location; correlated
    // handler domains satisfy the broader secondary-sensitive predicate.
    if(candidate.empty() || candidate==selected.artifact) return false;
    const auto found=profiles.find(candidate);if(found==profiles.end()) return false;
    if(runtime.reviewed_candidate_in_known_path(candidate,&found->second)) return false;
    return runtime.reviewed_secondary_domains(found->second.correlated_domains_at_24);
}
ByteString first_three_namespace_parts(Contracts& runtime,const ByteString& name) {
    const auto lower=runtime.original_unicode_lowercase(name);
    std::vector<ByteString> parts;std::size_t start=0;
    for(;;) {
        const auto dot=lower.find('.',start);
        if(dot==ByteString::npos) {parts.push_back(lower.substr(start));break;}
        parts.push_back(lower.substr(start,dot-start));start=dot+1;
    }
    if(parts.size()<3 || parts[0].empty() || parts[1].empty() || parts[2].empty()) return {};
    return parts[0]+"."+parts[1]+"."+parts[2];
}
using NamespaceCounts=std::map<ByteString,std::map<ByteString,std::int64_t>>;
NamespaceCounts namespace_counts(Contracts& runtime,const std::vector<Cluster>& clusters) {
    NamespaceCounts result;
    for(const auto& cluster:clusters) {
        const auto group=first_three_namespace_parts(runtime,cluster.namespace_name);
        if(group.empty() || cluster.artifact.empty()) continue;
        result[group][cluster.artifact]+=cluster.distinct_names;
    }
    return result; // loader is not part of this grouping
}
bool split_namespace_has_larger_artifact(Contracts& runtime,const Profiles& profiles,
    const Selection& selected,const NamespaceCounts& counts,const Cluster& cluster) {
    if(!secondary_sensitive(runtime,profiles,selected,cluster.artifact)) return false;
    const auto group=first_three_namespace_parts(runtime,cluster.namespace_name);
    const auto found=counts.find(group);if(found==counts.end() || found->second.size()<2) return false;
    const auto current=found->second.find(cluster.artifact);
    const auto current_count=current==found->second.end() ? 0 : current->second;
    for(const auto& entry:found->second)
        if(entry.first!=cluster.artifact && entry.second>current_count) return true;
    return false;
}
void evaluate(Contracts& runtime,const Profiles& profiles,const Selection& selected,
              const NamespaceCounts& groups,const Cluster& cluster) {
    const auto found=profiles.find(cluster.artifact);
    const bool sensitive=secondary_sensitive(runtime,profiles,selected,cluster.artifact);
    // Recovered @ 0x1e9586f: confidence + secondary-sensitive artifact.
    if(cluster.confidence_at_64 && sensitive)
        runtime.append_original_rule_match("SECONDARY_CLUSTER_SENSITIVE_HOOKS",85,
                                           cluster.namespace_name); //0x1e9586f
    // Recovered @ 0x1e877d9: an artifact under an exact mods component whose
    // aggregated profile records an unbacked candidate, dense correlated handler
    // domains, and at least 15 classes.
    if(found!=profiles.end() && runtime.reviewed_exact_mods_component(cluster.artifact) &&
       found->second.any_unbacked_at_9 &&
       runtime.reviewed_dense_domains(found->second.correlated_domains_at_24) &&
       found->second.class_count_at_32>=15)
        runtime.append_original_rule_match("MODS_CROSS_DOMAIN_COMBAT_BUNDLE",80,
                                           cluster.namespace_name); //0x1e877d9
    // Recovered @ 0x1e95974: a secondary-sensitive artifact shares its first
    // three lowercased namespace components with a strictly larger artifact.
    if(split_namespace_has_larger_artifact(runtime,profiles,selected,groups,cluster))
        runtime.append_original_rule_match("NAMESPACE_SPLIT_SENSITIVE_HOOKS",80,
                                           cluster.namespace_name); //0x1e95974
    // Recovered @ 0x1e871a0: a secondary-sensitive artifact profile contains
    // between one and eight classes inclusive.
    if(found!=profiles.end() && sensitive && found->second.class_count_at_32>=1 &&
       found->second.class_count_at_32<=8)
        runtime.append_original_rule_match("SECONDARY_SENSITIVE_INPUT_HOOKS",80,
                                           cluster.namespace_name); //0x1e871a0
}
//28 original returned cases:5 selection,2 secondary/mods,3 small-count,3 namespace
// split,15 grouping-helper boundaries. Preference is non-mods even with count0;
// all-mods falls back. Synthetic iteration ties retained input-first b.jar;
// the fixture's old label tie-byte-first was incorrect, not an original rule.
// Small-count5/8 pass,9 fails; larger21 vs20 within same first3 namespace
// components passes split rule; equal count or different prefix fails.
// Recovered: each matched rule appends evidence; maximum-score selection and tie
// behavior are handled by java_evidence_mutation.cpp.
// Producers and final admission/report selection are wired through
// java_artifact_profiles.cpp and java_complete_evidence_pipeline.cpp.
}
