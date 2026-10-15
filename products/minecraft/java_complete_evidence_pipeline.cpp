#include "java_complete_evidence_pipeline.hpp"
#include <array>
#include <tuple>

namespace ocean::reconstructed::minecraft_java_complete_pipeline {
// Purpose: show the end-to-end order of the Java class evidence pipeline.
// It first reconstructs classes and JAR ownership, then builds same-loader
// clusters, scores every eligible class, and retains representative findings.
bool ClusterKey::operator<(const ClusterKey &other) const {
  return std::tie(loader, artifact, namespace_name) <
         std::tie(other.loader, other.artifact, other.namespace_name);
}

struct StageBinding {
  std::string_view action, source;
};
static constexpr std::array<StageBinding, 33> kStageBindings{
    {{"open process, enumerate modules and select jvm.dll",
      "java_native_collection.cpp"},
     {"load six VMStruct exports and five bounded metadata maps",
      "java_hotspot_vmstructs.cpp"},
     {"bind the 23 remote-memory readers", "java_hotspot_reader_builder.cpp"},
     {"choose ClassLoaderDataGraph or SystemDictionary registry",
      "java_class_registry.cpp"},
     {"walk ClassLoaderDataGraph and mark bootstrap rows",
      "java_loader_graph_walk.cpp"},
     {"walk SystemDictionary buckets", "java_dictionary_walk.cpp"},
     {"assemble one 320-byte logical class record",
      "java_class_collection.cpp"},
     {"snapshot constant-pool tags, entries and UTF8 cache",
      "java_native_pool_snapshot.cpp"},
     {"render constant-pool values and references",
      "java_pool_constant_renderer.cpp"},
     {"select encoded or legacy field layout",
      "java_field_source_selection.cpp"},
     {"decode class, field and type annotations",
      "java_annotation_grammar.cpp"},
     {"collect raw methods and ConstMethod attributes",
      "java_raw_method_control_flow.cpp"},
     {"parse ConstMethod tail blobs", "java_const_method_control_flow.cpp"},
     {"walk bytecode and collect opcode bytes",
      "java_bytecode_instruction_walk.cpp"},
     {"resolve bytecode constant-pool operands",
      "java_bytecode_reference_flow.cpp"},
     {"classify native method slots and memory regions",
      "java_native_method_classifier.cpp"},
     {"build object-decoding context", "java_native_context.cpp"},
     {"read supported static field values", "java_static_field_collection.cpp"},
     {"cache classes by PID", "java_class_member_inventory.cpp"},
     {"collect JAR candidates from open files, command line and game "
      "directories",
      "java_process_artifact_inputs.cpp"},
     {"read JAR metadata and build class-owner/identifier maps",
      "java_jar_metadata_collection.cpp"},
     {"map mixin method owner IDs to artifact categories",
      "java_mixin_owner_enrichment.cpp"},
     {"build loader/artifact/namespace clusters",
      "java_cluster_name_rules.cpp"},
     {"attribute mixin handlers to same-loader clusters",
      "java_handler_cluster_attribution.cpp"},
     {"aggregate artifact profiles", "java_artifact_profiles.cpp"},
     {"apply name, obfuscation and hook rules",
      "java_cluster_name_rules.cpp; java_cluster_obfuscation_rules.cpp; "
      "java_cluster_hook_rules.cpp"},
     {"apply secondary artifact rules", "java_secondary_artifact_rules.cpp"},
     {"apply correlated module and injector rules",
      "java_correlated_module_rule.cpp; java_obfuscated_injector_rule.cpp"},
     {"apply game-provider rules with actual exclusion reachability",
      "java_game_provider_rules.cpp"},
     {"apply native-method rules", "java_native_method_rules.cpp"},
     {"apply owner and duplicate-loader rules",
      "java_owner_duplicate_rules.cpp"},
     {"append rule/context/artifact/profile/reference evidence",
      "java_evidence_mutation.cpp"},
     {"sort, group and retain three representatives",
      "java_final_evidence_filter.cpp"}}};

struct RuleBinding {
  std::string_view id;
  std::int64_t score;
  std::string_view condition_source;
};
// Recovered rule order from g2. apply_rule_match always
// appends RULE_MATCH; the selected winner changes only when candidate_score is
// greater.
static constexpr std::array<RuleBinding, 21> kRules{
    {{"CLUSTER_ARTIFACT_HOOKS", 85,
      "confidence, unbacked/temp/missing artifact, >1 hook-domain keys"},
     {"DENSE_CROSS_DOMAIN_HOOKS", 82,
      "confidence, eligible artifact, combat+network+(movement|entity_render)"},
     {"SECONDARY_CLUSTER_SENSITIVE_HOOKS", 85,
      "confidence and secondary-sensitive artifact"},
     {"MODS_CROSS_DOMAIN_COMBAT_BUNDLE", 80,
      "mods component, any unbacked input, dense domains, >=15 artifact "
      "classes"},
     {"UNBACKED_CROSS_DOMAIN_HOOKS", 88,
      "eligible artifact and dense domains; no direct confidence test"},
     {"NAMESPACE_SPLIT_SENSITIVE_HOOKS", 80,
      "secondary artifact shares first three namespace parts with a larger "
      "artifact"},
     {"SECONDARY_SENSITIVE_INPUT_HOOKS", 80,
      "secondary-sensitive artifact with 1..8 classes"},
     {"CLUSTER_UNBACKED_CONTROL_IDENTIFIERS", 85,
      "confidence, eligible artifact, namespace rune <32 or DEL"},
     {"UNBACKED_MASSIVE_OBFUSCATED_CLUSTER", 80,
      "confidence, eligible artifact, >=100 distinct names"},
     {"OBFUSCATED_INJECTOR_CLUSTER", 85,
      "all names obfuscated plus correlated hook/reference evidence"},
     {"SHORT_NAMESPACE_MASSIVE_OBFUSCATION", 82,
      "eligible artifact, all >=100 names obfuscated, namespace byte length "
      "<4"},
     {"PACKAGED_CLIENT_GAME_PROVIDER", 90,
      "packaged game artifact with dense all-category profile"},
     {"CORRELATED_CHEAT_MODULES", 92,
      "correlated explicit-module family within one loader/artifact/namespace "
      "bucket"},
     {"EXPLICIT_CHEAT_MODULE", 95,
      "at least one accepted explicit module simple name"},
     {"MODULE_MANAGER_GUI", 88,
      ">=2 GUI simple names, or exactly 1 and lowered namespace contains "
      "client"},
     {"MEMORY_INJECTED_GAME_CLASSES", 90,
      "eligible net.minecraft row and >=50 unowned game rows"},
     {"LIVE_GAME_CLASS_HANDLERS", 92,
      "net.minecraft row and any eligible dense handler cluster"},
     {"OWNER_ARTIFACT_SENSITIVE_HOOKS", 90,
      "attributed owner eligible/secondary and has >=2 domains"},
     {"CLUSTER_PRIVATE_NATIVE", 85,
      "confidence and unchanged native slot in private committed executable "
      "memory"},
     {"CLUSTER_ARTIFACT_NATIVE_BACKING", 80,
      "confidence, missing backing path and eligible cluster artifact"},
     {"DUPLICATE_CLUSTER_HOOKS", 80,
      "confidence, >=2 domains, exact class name in >=2 nonzero loaders"}}};

Result collect_java_evidence(ReviewedStages &runtime, std::uint32_t pid) {
  // Phase 1 — acquire and attribute evidence.
  // eOafqYa @ 0x1e75060: cache first. On error, do not collect artifacts.
  auto [classes, error] = runtime.cached_hotspot_classes(pid);
  if (error.present())
    return {{}, {}, error};

  // jCX -> eD -> g2. The returned path slice is not part of eOaf's result.
  auto artifacts = runtime.collect_process_artifacts(pid);
  runtime.enrich_artifact_categories(classes, artifacts);
  auto clusters = runtime.build_clusters(classes, artifacts);
  runtime.attribute_mixin_handlers(classes, clusters);
  runtime.build_artifact_profiles(classes, artifacts, clusters);
  runtime.prepare_global_rule_inputs(classes, artifacts, clusters);

  // Phase 2 — score each eligible, attributed class in the original order.
  std::vector<ClassEvidence> admitted;
  for (const auto &klass : classes) {
    // The real g2 caller skips bootstrap-marker rows and ZWi/gOg exclusions.
    // Because gOg excludes lowered "net.minecraft.", the three game-name
    // branches above are dormant for ordinary immutable rows in this build.
    if (klass.bootstrap_class || runtime.sdk_excluded_class(klass.name))
      continue;
    auto *cluster = runtime.cluster_for(klass, clusters);
    if (!cluster)
      continue;
    auto record =
        runtime.initial_evidence(klass, *cluster); // score starts at 0
    for (std::size_t index = 0; index < kRules.size(); ++index)
      runtime.apply_rule_group(index, klass, *cluster, record);
    // Original final admission is signed score > 69 (0x45).
    if (record.score <= 69)
      continue;
    runtime.append_selected_context_evidence(klass, *cluster, record);
    admitted.push_back(std::move(record));
  }

  // Phase 3 — collect the independent Unicode-name channel, then collapse
  // equivalent scored findings to representative rows.
  // jVad runs independently over the original class slice. It emits each exact
  // name once, in encounter order, when any decoded rune lies outside 32..126
  // and the shared exclusion predicate does not reject the name.
  auto unicode = runtime.collect_unicode_names(classes);
  // xlB sorts score DESC, class bytes ASC, loader-origin bytes ASC. Its raw
  // equivalence key concatenates RULE/CLUSTER/ARTIFACT type+":"+JSON, with
  // no separator between entries, and retains at most three records per key.
  auto representatives = runtime.select_representatives(admitted);
  return {std::move(representatives), std::move(unicode), {}};
}

// This file is wiring, not a second implementation of the component bodies.
// kStageBindings names every readable body used above. Go map iteration, JSON
// escaping, remote reads and OS calls remain explicit providers in those files.
// Review source only: never compiled or executed.
} // namespace ocean::reconstructed::minecraft_java_complete_pipeline
