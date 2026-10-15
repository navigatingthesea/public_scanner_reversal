#include "../../session/session_types.hpp"
#include <map>
#include <vector>
namespace ocean::reconstructed::minecraft_cluster_hook_rules {
struct Cluster {
    ByteString namespace_name;     // original context offset24
    ByteString candidate_artifact; // offset8, JAR-entry index provenance
    bool obfuscation_confidence=false; // offset64, reviewed Wilson predicate
    bool temporary_artifact=false;    // offset65
    bool missing_artifact=false;      // offset66, original Stat/IsNotExist
    std::map<ByteString,bool> hook_domains; // offset72, exact-key boolean map
};
struct RuleMatch {ByteString id;std::int64_t score;ByteString namespace_name;};
struct Selection {
    std::int64_t score=0;
    ByteString id;
    std::vector<RuleMatch> all_matches;
};
bool category(const Cluster& cluster,const ByteString& key) {
    const auto found=cluster.hook_domains.find(key);
    return found!=cluster.hook_domains.end() && found->second;
}
bool dense(const Cluster& cluster) {
    return category(cluster,"combat") && category(cluster,"network") &&
           (category(cluster,"movement") || category(cluster,"entity_render"));
}

// Interpretation: "unbacked" means no indexed artifact, a temporary-looking
// artifact name, or an absolute artifact path that was absent when scanned.
// It does not prove memory injection or malicious behavior.
bool artifact_is_unbacked_candidate(const Cluster& cluster) {
    return cluster.candidate_artifact.empty() || cluster.temporary_artifact ||
           cluster.missing_artifact;
}
void append(Selection& result,const Cluster& cluster,const ByteString& id,
            std::int64_t score) {
    // Recovered: nMB always appends RULE_MATCH; strictly greater replaces best.
    result.all_matches.push_back({id,score,cluster.namespace_name});
    if(score>result.score) {result.score=score;result.id=id;}
}
void evaluate(Selection& result,const Cluster& cluster) {
    const bool candidate=artifact_is_unbacked_candidate(cluster);
    // Recovered @ 0x1e95453: Wilson confidence + unbacked artifact + at least
    // two stored domain keys emits CLUSTER_ARTIFACT_HOOKS at score 85. Go
    // len(map) counts keys; it does not count true values.
    if(cluster.obfuscation_confidence && candidate &&
       cluster.hook_domains.size()>1)
        append(result,cluster,"CLUSTER_ARTIFACT_HOOKS",85);
    // Recovered @ 0x1e88895: same confidence and artifact gates, plus the exact
    // dense-domain predicate, emits DENSE_CROSS_DOMAIN_HOOKS at score 82.
    if(cluster.obfuscation_confidence && candidate && dense(cluster))
        append(result,cluster,"DENSE_CROSS_DOMAIN_HOOKS",82);
    // Recovered @ 0x1e95a5a: unbacked artifact + dense domains emits
    // UNBACKED_CROSS_DOMAIN_HOOKS at score 88. This branch has no direct Wilson
    // confidence test; upstream category production has separate gates.
    if(candidate && dense(cluster))
        append(result,cluster,"UNBACKED_CROSS_DOMAIN_HOOKS",88);
}
// Recovered: these rules are reached for every eligible member of the attributed
// bucket. Later final filtering retains up to three equivalent representatives. All matches
// remain evidence even when a higher-scoring rule becomes the selected rule.
// The six full SDK cases verified one/two/three domains, different loader,
// existing artifact, and empty owner-index value. With21 members (20 short
// obfuscated names), Aero handler attack+packet gives85; adding movement gives
// 85,82,88 matches and final88. Original categories and examples are retained
// in report evidence.
// Interpretation: this is a generic handler-domain path, not an Aero brand test.
// Native/JAR/Stat inputs are synthetic analysis contracts; no C++ or sample
// execution. Other SDK rules and the attribution fallback are mapped in adjacent source files.
}
