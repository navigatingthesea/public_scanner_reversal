#include "../../session/session_types.hpp"
#include <map>
#include <vector>
namespace ocean::reconstructed::minecraft_artifact_profiles {
using DomainMap=std::map<ByteString,bool>;
struct Cluster {
    ByteString artifact;
    std::int64_t obfuscated_names=0;
    std::int64_t distinct_names=0;
    bool confidence=false,temporary=false,missing=false;
    DomainMap handler_domains;
};
// Recovered: original type 3769080 is 40 bytes, including flag alignment.
struct ArtifactProfile {
    std::int64_t obfuscated_at_0=0;
    bool any_confident_cluster_at_8=false;
    bool any_unbacked_candidate_at_9=false;
    DomainMap all_domains_at_16;
    DomainMap handler_domains_at_24;
    std::int64_t classes_at_32=0;
};
struct ClassInput {
    ByteString full_name,candidate_artifact;
    bool raw_skip_at_224=false;
};
struct Contracts {
    virtual bool original_sdk_class_exclusion(const ByteString&)=0; // ZWi/gOg
    virtual std::vector<ByteString> reviewed_class_mixin_domains(const ByteString&)=0;
};
using Profiles=std::map<ByteString,ArtifactProfile>;
Profiles aggregate_clusters(const std::vector<Cluster>& clusters) {
    Profiles profiles;
    for(const auto& cluster:clusters) {
        // Recovered: keys are byte exact and the empty artifact key is retained.
        auto& profile=profiles[cluster.artifact];
        profile.obfuscated_at_0+=cluster.obfuscated_names;
        profile.classes_at_32+=cluster.distinct_names;
        profile.any_confident_cluster_at_8 |= cluster.confidence;
        profile.any_unbacked_candidate_at_9 |= cluster.artifact.empty() ||
                                             cluster.temporary || cluster.missing;
        // Recovered: the range loop copies domain keys and writes true to both
        // the broad feature map and handler-only map.
        for(const auto& entry:cluster.handler_domains) {
            profile.all_domains_at_16[entry.first]=true;
            profile.handler_domains_at_24[entry.first]=true;
        }
    }
    return profiles;
}
void add_class_name_domains(Contracts& runtime,Profiles& profiles,
                            const std::vector<ClassInput>& classes) {
    for(const auto& klass:classes) {
        if(klass.raw_skip_at_224 ||
           runtime.original_sdk_class_exclusion(klass.full_name)) continue;
        auto& profile=profiles[klass.candidate_artifact];
        // Recovered: cG requires a namespace dot and a simple class name with a
        // Mixin/accessor marker, then applies the 35-keyword domain matcher. The
        // jU9 library-name gate is not used in this pass.
        for(const auto& domain:runtime.reviewed_class_mixin_domains(klass.full_name))
            profile.all_domains_at_16[domain]=true;
    }
}
void add_external_feature_domains(Profiles& profiles,
    const std::map<ByteString,DomainMap>& features) {
    for(const auto& entry:features) {
        if(entry.first.empty() || entry.second.empty()) continue;
        auto found=profiles.find(entry.first);
        // Recovered: external features enrich an existing cluster profile; they
        // never create a profile on their own.
        if(found==profiles.end()) continue;
        for(const auto& domain:entry.second)
            found->second.all_domains_at_16[domain.first]=true;
    }
}
// Recovered: artifact keys use exact bytes, with no case-folding or path
// normalization at lookup.
// External false-valued categories (including an empty category key) are copied
// as true. Only entry-key emptiness and source-map cardinality are gated.
// Count aggregation is over already distinct-name clusters: same raw class twice
// in one cluster counts1, the same name in two loaders/namespaces can count2.
// Thirty original fixtures verified counts/flags, Mixin class domains, provided
// categories, key/value boundaries, and full Aero handler correlation. The Aero
// fixture had obfuscated_at_0=20, classes_at_32=21, both flags set, and three
// domains in both maps. Interpretation: Aero is fixture metadata flowing through
// generic aggregation; there is no brand-specific branch here.
// Unresolved: raw class/reference production and final serialization are outside
// this unit.
// Generated in VM; no C++ compilation/execution or native/sample execution.
}
