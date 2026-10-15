#include "../../session/session_types.hpp"
#include <set>
#include <unordered_map>
#include <vector>
namespace ocean::reconstructed::minecraft_owner_duplicate_rules {
struct Cluster {
    ByteString artifact;
    bool confidence,temporary,missing;
    std::set<ByteString> domains;
};
struct Correlation {Cluster* owner;ByteString method_name,domain;};
using LoaderIndex=std::unordered_map<ByteString,std::set<std::uint64_t>>;
struct Contracts {
    virtual bool reviewed_secondary_artifact_gate(const ByteString&)=0;
    virtual void append_original_rule_match(const ByteString&,std::int64_t)=0;
    virtual void append_original_owner_evidence(const Correlation&)=0;
    virtual void append_original_duplicate_evidence(std::size_t)=0;
};
void index_loader(LoaderIndex& index,const ByteString& class_name,std::uint64_t loader) {
    if(loader!=0) index[class_name].insert(loader);
}
void evaluate_owner(Contracts& output,const std::vector<Correlation>& host_events) {
    // Recovered: the original map indexes the host input row, not only its name,
    // so duplicate accepted events remain duplicate evidence rows.
    for(const auto& event:host_events) {
        const auto& owner=*event.owner;
        const bool eligible=owner.artifact.empty() || owner.temporary || owner.missing;
        if(!eligible && !output.reviewed_secondary_artifact_gate(owner.artifact)) continue;
        // Recovered gates: unbacked/temporary/missing or secondary-sensitive
        // artifact, and at least two stored owner-domain keys. No direct
        // confidence or dense-domain requirement applies here.
        if(owner.domains.size()<2) continue;
        output.append_original_rule_match("OWNER_ARTIFACT_SENSITIVE_HOOKS",90);//1e84598
        output.append_original_owner_evidence(event);
    }
}
void evaluate_duplicate(Contracts& output,const Cluster& current,const LoaderIndex& index,
                        const ByteString& exact_class_name) {
    // Recovered gates: confidence, at least two stored domain keys, and the exact
    // class name observed under more than one nonzero loader identity.
    if(!current.confidence || current.domains.size()<=1) return;
    const auto it=index.find(exact_class_name);
    if(it==index.end() || it->second.size()<=1) return;
    output.append_original_rule_match("DUPLICATE_CLUSTER_HOOKS",80);//1e99f93
    output.append_original_duplicate_evidence(it->second.size());
}
// Recovered: same-loader duplicate rows deduplicate; loader zero is omitted and
// class-name matching is byte exact.
// No artifact path gate in duplicate80. Owner90 does not directly require confidence
// or the dense-domain predicate; it needs2 distinct domains in its correlated owner.
// Earlier attribution still determines whether each event exists (source126/129).
// Caller excludes flag224 rows and ZWi library-name rows from cluster/scoring passes.
// Therefore net.minecraft.* host tests produced attribution events but no owner-score
// row, while p.Host received90 twice for its2 distinct accepted handler events.
//12 original full SDK fixtures returned, including nonconfident linked-reference
// attribution, same/different/zero loaders, existing vs temp, and one domain.
// Exact evidence encoding and broader caller integration are separately reviewed.
// VM-only review source, never compiled or run.
}
