#include "../../session/session_types.hpp"
#include <set>
#include <vector>
namespace ocean::reconstructed::minecraft_correlated_module_rule {
struct NameInput {ByteString full_name,simple_name;};
struct Contracts {
    virtual bool reviewed_library_name_gate(const ByteString&)=0;
    virtual bool reviewed_primary_module_predicate(const ByteString&)=0; //yrn
    virtual bool reviewed_embedded_strong_module_predicate(const ByteString&)=0; //zilq
    virtual bool reviewed_generic_26_module_predicate(const ByteString&)=0; //aFQ
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
    virtual void append_original_rule_match(const ByteString&,std::int64_t,
                                            const ByteString&)=0;
};
ByteString strip_one_suffix(ByteString name,const ByteString& suffix) {
    if(name.size()>=suffix.size() &&
       name.compare(name.size()-suffix.size(),suffix.size(),suffix)==0)
        name.resize(name.size()-suffix.size());
    return name;
}
struct BucketNames {
    std::vector<ByteString> strong_match_names;
    std::set<ByteString> generic_normalized_names;
};
void collect(Contracts& runtime,BucketNames& bucket,const NameInput& name) {
    // Recovered gate: library/framework class names contribute nothing.
    if(runtime.reviewed_library_name_gate(name.full_name)) return;

    // Recovered: any strong predicate match suppresses generic-name collection
    // for this row and is remembered separately for the bucket-wide gate.
    if(runtime.reviewed_primary_module_predicate(name.simple_name) ||
       runtime.reviewed_embedded_strong_module_predicate(name.simple_name)) {
        bucket.strong_match_names.push_back(name.simple_name);
        return;
    }
    if(!runtime.reviewed_generic_26_module_predicate(name.simple_name)) return;
    // Caller order differs from aFQ's predicate: strip on ORIGINAL bytes first.
    // Comparisons to literal lowercase suffixes are case-sensitive.
    auto key=strip_one_suffix(name.simple_name,"module");
    key=strip_one_suffix(key,"util");
    key=strip_one_suffix(key,"utils");
    key=runtime.original_unicode_lowercase(key);
    bucket.generic_normalized_names.insert(key);
}
void evaluate(Contracts& runtime,const BucketNames& bucket,const ByteString& ns) {
    // Recovered: exact g2 call at 0x1e961d2. A full
    // loader/artifact/namespace bucket emits CORRELATED_CHEAT_MODULES (92) when
    // it contains at least two distinct normalized generic names and no strong
    // module-name match. Scores are handled by the shared rule sink.
    if(bucket.strong_match_names.empty() && bucket.generic_normalized_names.size()>=2)
        runtime.append_original_rule_match("CORRELATED_CHEAT_MODULES",92,ns);
}
// No Wilson, minimum-class-count, client namespace, temporary or missing-artifact
// gate in this rule. The rule propagates to ordinary members of the same bucket.
// Aura+ESP give92; KillAura in that bucket suppresses this rule in favor of the
// strong-name path. AuraModule+AuraUtil give92 because keys remain auramodule
// and aurautil. auramodule+aurautil, or Auramodule+Aurautil, collapse to aura.
// Aura$One+Aura$Two count2, despite matching the same generic keyword.
//13 original full SDK cases returned, including key partition/library boundaries.
// Interpretation: these are heuristic class-name correlations, not independent
// proof that a module is active or malicious.
// Source generated inside VM, uncompiled/unexecuted.
}
