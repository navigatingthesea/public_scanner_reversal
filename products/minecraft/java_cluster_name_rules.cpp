#include "../../session/session_types.hpp"
#include <map>
#include <set>
#include <tuple>

namespace ocean::reconstructed::minecraft_cluster_name_rules_review {
using Word = std::uint64_t;
using NameSet = std::set<ByteString>;
struct RawClass {
    ByteString name_at_0;
    Word loader_identity_at_216 = 0;
    bool skip_at_224 = false; // bootstrap-class marker from loader graph; dictionary mode is false
};
struct ClusterKey {
    Word loader = 0;
    ByteString indexed_artifact; // original class-name JAR index, not CodeSource
    ByteString namespace_name;
    bool operator<(const ClusterKey& rhs) const {
        return std::tie(loader, indexed_artifact, namespace_name) <
               std::tie(rhs.loader, rhs.indexed_artifact, rhs.namespace_name);
    }
};
struct Cluster {
    ClusterKey key;                         // original104B context key0..39
    NameSet distinct_simple_names;          // original map[string]bool+40
    GoInt obfuscated_names = 0;             // original int+48
    GoInt distinct_class_count = 0;         // original len(map at+40)
    GoInt namespace_class_count = 0;        // original int+56; crosses artifacts
    NameSet explicit_module_names;
    NameSet gui_component_names;
};
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
    // Existing separately recovered predicates. No native/file calls here.
    virtual bool original_library_name_gate(const ByteString&) = 0; // jU9, separate reviewed file
    virtual bool original_sdk_exclusion(const ByteString&) = 0; // ZWi -> gOg
    virtual bool original_obfuscated_identifier(const ByteString&) = 0; // bwml
    virtual bool original_explicit_module_name(const ByteString&) = 0; // yrn
    virtual bool original_gui_component_name(const ByteString&) = 0; // fj9
    // Go map iteration order is unspecified. This is deliberately a contract:
    // arbitrary sorting would change JSON bytes and later evidence grouping.
    virtual std::vector<ByteString> original_map_iteration(const NameSet&) = 0;
};
struct RuleSink {
    // Delegates to reviewed nMB: always appends RULE_MATCH; only strictly
    // greater score changes selected rule/context. Scores are not summed.
    virtual void apply_rule_match(const ByteString& id, GoInt score,
                                  const Cluster& context) = 0;
    // Delegates to reviewed qcAG: marshal error ignored, raw bytes copied.
    virtual void append_string_array_evidence(const ByteString& kind,
        const ByteString& field, const std::vector<ByteString>& names) = 0;
};

ByteString namespace_of(const ByteString& name) { // fuZu@1e66f00
    const auto dot = name.rfind('.');
    return dot == ByteString::npos ? ByteString{} : name.substr(0, dot);
}
ByteString simple_name_of(const ByteString& name) {
    const auto dot = name.rfind('.');
    return dot == ByteString::npos ? name : name.substr(dot + 1);
}

// Recovered: logical view of the name-rule bucket inputs in g2 @ 0x1e7b320.
// The full SDK also builds hook, loader, and constant-pool contexts in adjacent
// units. Artifact lookup here uses the exact FULL class name. A simple-name owner
// key is ignored in tested original SDK paths; artifact spelling in cluster
// keys is byte sensitive (C:/A.jar and c:/a.JAR are separate buckets).
std::map<ClusterKey, Cluster> build_name_rule_buckets(
    Contracts& runtime, const std::vector<RawClass>& classes,
    const std::map<ByteString, ByteString>& class_name_jar_index) {
    std::map<ClusterKey, Cluster> buckets;
    std::map<std::pair<Word,ByteString>,NameSet> namespace_names;
    for (const auto& record : classes) {
        if (record.skip_at_224 || runtime.original_sdk_exclusion(record.name_at_0))
            continue;
        const auto owner = class_name_jar_index.find(record.name_at_0);
        ClusterKey key{record.loader_identity_at_216,
            owner == class_name_jar_index.end() ? ByteString{} : owner->second,
            namespace_of(record.name_at_0)};
        auto& bucket = buckets[key];
        bucket.key = key;
        const auto simple = simple_name_of(record.name_at_0);
        namespace_names[{key.loader,key.namespace_name}].insert(simple);
        if (bucket.distinct_simple_names.insert(simple).second) {
            ++bucket.distinct_class_count;
            if (runtime.original_obfuscated_identifier(simple)) ++bucket.obfuscated_names;
        }
        if (!runtime.original_library_name_gate(record.name_at_0) &&
            runtime.original_explicit_module_name(simple))
            bucket.explicit_module_names.insert(simple);
        if (!runtime.original_library_name_gate(record.name_at_0) &&
            runtime.original_gui_component_name(simple))
            bucket.gui_component_names.insert(simple);
    }
    for(auto& entry:buckets) {
        auto& bucket=entry.second;
        bucket.namespace_class_count=static_cast<GoInt>(
            namespace_names[{bucket.key.loader,bucket.key.namespace_name}].size());
    }
    return buckets;
}

// Recovered: call for each eligible class record with its matching bucket. A rule describes
// the whole bucket, so an ordinary App class can receive score95/88 because
// another class in the same loader/artifact/namespace supplied the match.
// Duplicate raw class rows can remain duplicate outputs; name sets only dedup
// aggregate counts. Final cap/score-output gates are not implemented here.
void apply_name_rules_for_class(Contracts& runtime, RuleSink& output,
                                const Cluster& bucket) {
    // Recovered: g2.func19, nMB call at 0x1e86500. Any strong module-name
    // category in the bucket emits EXPLICIT_CHEAT_MODULE (95) and a CHEAT_MODULES
    // evidence array. The rule is tested even for an empty namespace.
    if (!bucket.explicit_module_names.empty()) {
        output.apply_rule_match("EXPLICIT_CHEAT_MODULE", 95, bucket);
        output.append_string_array_evidence("CHEAT_MODULES", "classes",
            runtime.original_map_iteration(bucket.explicit_module_names));
    }
    // Recovered: count unique matching SIMPLE NAMES, not GUI keyword tokens.
    // ModuleManager and X$ModuleManager meet2; duplicated ModuleManager does not.
    // Also accepts exactly1matching name if Unicode-lowercased namespace
    // CONTAINS "client" anywhere; no token/component/suffix boundary required.
    // BBU@243d80 calls Index and tests>=0: Contains, not HasSuffix.
    // g2.func44, nMB call at 0x1e85dba, score 0x58 (88).
    const bool one_gui_in_client_namespace = bucket.gui_component_names.size() == 1 &&
        runtime.original_unicode_lowercase(bucket.key.namespace_name).find("client") != ByteString::npos;
    if (bucket.gui_component_names.size() >= 2 || one_gui_in_client_namespace) {
        output.apply_rule_match("MODULE_MANAGER_GUI", 88, bucket);
        output.append_string_array_evidence("CHEAT_MODULES", "gui_components",
            runtime.original_map_iteration(bucket.gui_component_names));
    }
}
// Recovered: 40 original rule/group/prefix fixtures, eight small-name groups, and
// four large neutral groups returned. The explicit rule runs before GUI in a
// combined bucket; both RULE_MATCH rows remain, while score 95 wins. Loader,
// artifact, or namespace splits prevent name evidence from spreading buckets.
// raw216 is the loader identity; changes at 208/256/296 did not split fixtures.
//
// Recovered: net.minecraft/com.mojang/org.lwjgl names are excluded even when
// raw224 is false; java/kotlin and empty namespaces passed tested paths. The exact
// 23-prefix predicate is in java_class_member_inventory.cpp.
// Unresolved: runtime JSON/order and native production remain contracts here.
// Never compile or run this file.
}

// Recovered corrections: 18 additional fixtures proved the single-GUI-name plus
// namespace Contains("client") path. context+56 is a loader+namespace-wide
// distinct count spanning artifacts, while distinct_class_count is map40 size.
// The jU9 full-name gate suppresses module/GUI keyword contributions while class
// and namespace counts remain. The exact gate is in java_library_name_gate.cpp.
