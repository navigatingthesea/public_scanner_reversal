#include "../../session/session_types.hpp"
#include <set>
#include <unordered_map>
#include <vector>
namespace ocean::reconstructed::minecraft_game_provider_rules {
struct Class {ByteString name,artifact;bool skip224=false;};
struct Cluster {ByteString artifact;bool temporary=false,missing=false;std::set<ByteString> domains;};
struct Artifact {std::set<ByteString> all_categories;}; // reviewed profile map+16
using Profiles=std::unordered_map<ByteString,Artifact>;
struct Inputs {
    std::int64_t unowned_game_rows=0;
    bool any_eligible_dense_cluster=false;
    std::set<ByteString> packaged_game_artifacts;
};
bool game_prefix(const ByteString& name) {return name.size()>=14 && name.compare(0,14,"net.minecraft.")==0;}
bool dense(const std::set<ByteString>& categories) {
    return categories.count("combat") && categories.count("network") &&
           (categories.count("movement") || categories.count("entity_render"));
}
Inputs prepare(const std::vector<Class>& original_rows,const std::vector<Cluster>& clusters,
               const Profiles& profiles,bool owner_map_nonnull) {
    Inputs result;
    // Recovered: this counting pass checks flag 224 but does not apply ZWi.
    // It counts raw net.minecraft.* rows with no artifact only when the owner map
    // itself is nonnull; duplicates remain separate rows.
    for(const auto& row:original_rows) {
        if(row.skip224 || !game_prefix(row.name)) continue;
        if(owner_map_nonnull && row.artifact.empty()) ++result.unowned_game_rows;
    }
    // Recovered: this process-wide flag becomes true when any cluster combines
    // an unbacked artifact with the exact dense-domain predicate.
    for(const auto& cluster:clusters)
        if((cluster.artifact.empty() || cluster.temporary || cluster.missing) &&
           dense(cluster.domains)) {result.any_eligible_dense_cluster=true;break;}
    return result;
}
struct Contracts {
    virtual bool reviewed_ZWi_library_exclusion(const ByteString&)=0;
    virtual void append_original_rule_match(const ByteString&,std::int64_t)=0;
};
void prepare_packaged_artifacts(Contracts& runtime,Inputs& result,
        const std::vector<Class>& rows,const Profiles& profiles) {
    // Recovered: build from the filtered class-to-bucket index. A packaged game
    // artifact requires a nonempty artifact, a net.minecraft.* row that survives
    // flag 224 and ZWi, and an existing profile with at least one category.
    for(const auto& row:rows) {
        if(row.skip224 || runtime.reviewed_ZWi_library_exclusion(row.name) ||
           !game_prefix(row.name) || row.artifact.empty()) continue;
        const auto it=profiles.find(row.artifact);
        if(it!=profiles.end() && !it->second.all_categories.empty())
            result.packaged_game_artifacts.insert(row.artifact);
    }
}
void evaluate(Contracts& output,const Inputs& input,const Profiles& profiles,
              const Class& current,const Cluster& current_cluster) {
    // Recovered caller gate: flag 224 or ZWi/gOg exclusion suppresses every rule
    // below for the current class.
    if(current.skip224 || output.reviewed_ZWi_library_exclusion(current.name)) return;
    const auto profile=profiles.find(current_cluster.artifact);
    // Recovered: PACKAGED_CLIENT_GAME_PROVIDER (90) requires the current
    // artifact to be marked packaged and its broad profile map to be dense.
    if(input.packaged_game_artifacts.count(current_cluster.artifact) &&
       profile!=profiles.end() && dense(profile->second.all_categories))
        output.append_original_rule_match("PACKAGED_CLIENT_GAME_PROVIDER",90);//1e95d75
    // Recovered: MEMORY_INJECTED_GAME_CLASSES (90) additionally requires a
    // current net.minecraft.* class in an unbacked artifact and at least 50
    // process-wide unowned game rows.
    if(game_prefix(current.name) &&
       (current_cluster.artifact.empty() || current_cluster.temporary || current_cluster.missing) &&
       input.unowned_game_rows>=50)
        output.append_original_rule_match("MEMORY_INJECTED_GAME_CLASSES",90);//1e96cc5
    // Recovered: LIVE_GAME_CLASS_HANDLERS (92) requires a current game class and
    // any process-wide eligible dense cluster.
    if(game_prefix(current.name) && input.any_eligible_dense_cluster)
        output.append_original_rule_match("LIVE_GAME_CLASS_HANDLERS",92);//1e96e0e
}
// Inputs are global across original records/clusters, not per loader/current class.
// Memory count counts rows, not unique names; nonnull owner map is explicitly required.
// Packaged preparation marks artifacts when a FILTERED game row has existing nonempty all-
// category profile. Final dense predicate uses ALL categories, not handler-only map24.
// Condition alone would give an ordinary class in that artifact packaged90. No direct
// confidence or mods-path gate in packaged90. Caller ZWi excludes every Unicode-
// lowercase net.minecraft.* row. Consequently memory/live branches are dormant for
// ordinary fixed class records in this captured build. The packaged marking pass
// also uses a filtered index, so it cannot mark excluded game rows in this build.
//15 original SDK probes returned: actual3domain host/actual50 rows no game scores;
// explicit ISOLATED ZWi=false probes expose49/50 boundary, global live propagation,
// dense/two-domain/empty-owner packaged boundaries, actual packaged propagation
// negative, flag224 game marker negative and nil-owner-map memory count negative.
// Interpretation: the isolated ZWi=false provider exposed the conditions but is
// absent from this source; those tests do not prove the memory/live rules are
// reachable with ordinary records in the captured build.
// Unresolved: exact JSON evidence encoding remains separate.
// Readable C++ generated inside VM, never compiled or run.
}
