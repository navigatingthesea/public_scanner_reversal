#include "../../session/session_types.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <tuple>
#include <vector>
namespace ocean::reconstructed::minecraft_handler_cluster_attribution {
struct Key {
    std::uint64_t loader=0;
    ByteString artifact,namespace_name;
    bool operator<(const Key& other) const {
        return std::tie(loader,artifact,namespace_name)<
               std::tie(other.loader,other.artifact,other.namespace_name);
    }
};
struct Cluster {
    Key key;
    std::vector<ByteString> distinct_simple_names;
    bool obfuscation_confidence=false;
    std::map<ByteString,bool> hook_domains;
    std::vector<ByteString> hook_examples;
};
struct HostClass {
    ByteString name;
    std::uint64_t loader_at_216=0;
    // The raw references at232 are supplied to the separately reviewed gVL
    // helper by the runtime contract below; methods at128 supply name_at_0.
};
struct Correlation {
    Key target;
    ByteString method_name;
    std::vector<ByteString> domains;
    std::vector<ByteString> linked_reference_examples;
};
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
    virtual ByteString original_kDR_method_owner(const ByteString&)=0; // reviewed parser
    virtual ByteString original_d8_fallback_owner(const ByteString&)=0; // reviewed java_fallback_method_owner.cpp
    virtual std::vector<ByteString> original_wqi_hook_domains(const ByteString&)=0;
    virtual std::vector<ByteString> linked_reference_examples(
        const HostClass&,const Cluster&)=0; // reviewed java_linked_reference_examples.cpp
};
std::vector<ByteString> dot_parts(const ByteString& value) {
    std::vector<ByteString> out;std::size_t start=0;
    for(;;) {
        const auto dot=value.find('.',start);
        if(dot==ByteString::npos) {out.push_back(value.substr(start));break;}
        out.push_back(value.substr(start,dot-start));start=dot+1;
    }
    return out; // Go Split preserves empty components
}
using Index=std::map<std::uint64_t,std::map<ByteString,std::set<Key>>>;

// Recovered: build a lookup per exact loader identity. Each lowercase namespace
// component and simple class name of at least four bytes points to its cluster.
// The four-byte threshold is byte length, not Unicode-rune count.
Index build_index(Contracts& runtime,const std::vector<Cluster>& clusters) {
    Index index;
    for(const auto& cluster:clusters) {
        for(const auto& part:dot_parts(cluster.key.namespace_name)) {
            const auto lower=runtime.original_unicode_lowercase(part);
            if(lower.size()>=4) index[cluster.key.loader][lower].insert(cluster.key);
        }
        for(const auto& name:cluster.distinct_simple_names) {
            const auto lower=runtime.original_unicode_lowercase(name);
            if(lower.size()>=4) index[cluster.key.loader][lower].insert(cluster.key);
        }
    }
    return index;
}
std::vector<Key> candidates(const Index& index,std::uint64_t loader,
                            const ByteString& token) {
    const auto by_loader=index.find(loader);if(by_loader==index.end()) return {};
    const auto by_token=by_loader->second.find(token);
    if(by_token==by_loader->second.end()) return {};
    std::vector<Key> out(by_token->second.begin(),by_token->second.end());
    // Recovered: hY orders namespace then artifact and ignores loader.
    // All entries here already share the exact queried loader.
    std::sort(out.begin(),out.end(),[](const Key& a,const Key& b) {
        return std::tie(a.namespace_name,a.artifact)<
               std::tie(b.namespace_name,b.artifact);
    });
    return out;
}
ByteString prefix_through_first_id(const std::vector<ByteString>& parts,
                                  const ByteString& id,bool& matched) {
    ByteString prefix;matched=false;
    for(std::size_t k=0;k<parts.size();++k) {
        if(k) prefix+='.';prefix+=parts[k];
        if(parts[k]==id) {matched=true;return prefix;}
    }
    return {};
}
void attribute_one_method(Contracts& runtime,const Index& index,
    const HostClass& host,const ByteString& original_method_name,
    std::map<Key,Cluster>& contexts,std::vector<Correlation>& host_correlations) {
    // Recovered gate 1: parse the owner identifier from a supported Mixin-style
    // method name. Failure means this method contributes no correlation.
    const auto id=runtime.original_kDR_method_owner(original_method_name);
    if(id.empty()) return;

    // Recovered gate 2: candidates must share the host's exact loader identity.
    // d8 supplies a lookup fallback only; the prefix-uniqueness test below still
    // uses the primary kDR identifier.
    auto selected=candidates(index,host.loader_at_216,id);
    if(selected.empty()) {
        const auto fallback=runtime.original_d8_fallback_owner(original_method_name);
        if(!fallback.empty()) selected=candidates(index,host.loader_at_216,fallback);
    }
    if(selected.empty()) return;
    std::set<ByteString> nonempty_artifacts,prefixes;
    for(const auto& key:selected) {
        if(!key.artifact.empty()) nonempty_artifacts.insert(key.artifact);
        bool matched=false;
        const auto prefix=prefix_through_first_id(dot_parts(
            runtime.original_unicode_lowercase(key.namespace_name)),id,matched);
        if(matched) prefixes.insert(prefix);
    }
    // Recovered gate 3: selected candidates collectively need exactly one
    // NONEMPTY artifact and exactly one namespace prefix through the primary ID.
    // This does not require one candidate bucket. Empty-artifact candidates stay
    // eligible when another candidate supplies the sole nonempty owner.
    if(nonempty_artifacts.size()!=1 || prefixes.size()!=1) return;
    // Recovered gate 4: a zero loader identity is never correlated.
    if(host.loader_at_216==0) return;

    // Recovered gate 5: the method name must map to at least one exact hook
    // domain. Empty domain output ends the route.
    const auto domains=runtime.original_wqi_hook_domains(
        runtime.original_unicode_lowercase(original_method_name));
    if(domains.empty()) return;
    for(const auto& key:selected) {
        auto found=contexts.find(key);if(found==contexts.end()) continue;
        auto& context=found->second;
        const auto examples=runtime.linked_reference_examples(host,context);
        // Recovered gate 6: the target needs either its obfuscation-confidence
        // flag or at least one linked constant-pool reference example.
        if(!context.obfuscation_confidence && examples.empty()) continue;
        host_correlations.push_back({key,original_method_name,domains,examples});
        for(const auto& domain:domains) context.hook_domains[domain]=true;
        // Recovered: this producer neither deduplicates nor caps examples at three.
        context.hook_examples.push_back(host.name+"::"+original_method_name);
    }
}
// Recovered: the primary parser accepts "aero" as an ordinary identifier.
// Namespace-only aero.client tokens suffice; no class literally named Aero is
// required. The same artifact owning aero.client and aero.other can receive
// evidence in both buckets because both share prefix "aero". Conversely,
// p.aero.client and q.aero.client are ambiguous. Artifact spelling is
// byte-sensitive, so path case differences can also create ambiguity.
//
// Recovered: there is no Minecraft host-name gate here; p.Host exercised a
// positive full-SDK fixture. Accepted correlations add domains and an uncapped,
// non-deduplicated "Host::method" example. Later rules decide whether to score
// the cluster.
//
// Interpretation: this is generic Mixin-owner attribution, not an Aero/Xaero
// brand check.
// Unresolved: production of the raw class references used by
// linked_reference_examples remains outside this function.
// All synthetic original-instruction fixtures stayed in VM. Never compile/run.
}

// Recovered: d8 fallback is reviewed separately as a fourth cleaned field with
// 12 prefixes. Even when d8 supplies lookup candidates, namespace-prefix
// validation continues to use kDR's third-field ID.
