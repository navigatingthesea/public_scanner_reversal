#pragma once
#include "../../session/session_types.hpp"
#include <cstdint>
#include <map>
#include <set>
#include <string_view>
#include <vector>

namespace ocean::reconstructed::minecraft_java_complete_pipeline {
// Canonical logical types shared by the recovered HotSpot class scanner,
// artifact attribution, rule scoring, and final evidence selection pipeline.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;

struct ErrorWords {
  std::uint64_t type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct Annotation {
  ByteString type, target, rendered;
  Bytes raw;
};
struct Reference {
  std::uint16_t constant_pool_index = 0;
  ByteString kind, owner, member, descriptor, rendered;
};
struct NativeMethodFacts {
  bool access_is_native = false;             // method+136
  bool slot_read_succeeded = false;          // method+216
  bool slot_unchanged = false;               // method+256
  bool query_succeeded = false;              // method+257
  bool private_committed_executable = false; // method+258
  bool backing_path_missing = false;         // method+259
  Address native_address = 0;                // method+208
  ByteString containing_module;              // method+224
  ByteString mapped_backing_name;            // method+240
};
struct Method {
  ByteString name, descriptor, generic_signature, sha256;
  std::vector<Annotation> annotations, parameter_annotations, type_annotations;
  Bytes bytecode, opcodes;
  std::vector<Reference> references;
  NativeMethodFacts native;
  bool bytecode_truncated = false;
};
struct Field {
  ByteString name, descriptor, generic_signature;
  std::vector<Annotation> annotations, type_annotations;
  ByteString rendered_static_value;
};
struct ClassRecord {
  ByteString name;
  std::vector<ByteString> pool_strings;
  ByteString generic_signature;
  std::vector<ByteString> interfaces;
  std::vector<Annotation> annotations, type_annotations;
  std::vector<Method> methods;
  std::vector<Field> fields;
  Bytes evidence_corpus;
  bool evidence_corpus_full = false;
  Address klass = 0;
  Address class_loader_data = 0;
  bool bootstrap_class =
      false; // loader-graph marker; dictionary walk yields false
  std::vector<Reference> references;
  Address superclass = 0;
  std::uint32_t parse_errors = 0, unsupported_values = 0;
};
struct ArtifactInputs {
  std::map<ByteString, ByteString> class_owners;
  std::map<ByteString, std::set<ByteString>> sensitive_categories;
  std::map<ByteString, ByteString> identifiers;
  std::vector<ByteString> paths;
};
struct ClusterKey {
  Address loader = 0;
  ByteString artifact, namespace_name;
  bool operator<(const ClusterKey &other) const;
};
struct Cluster {
  ClusterKey key;
  std::set<ByteString> simple_names, explicit_modules, gui_components;
  std::set<ByteString> hook_domains;
  std::vector<ByteString> hook_examples, linked_reference_examples;
  std::int64_t distinct_names = 0, obfuscated_names = 0, namespace_names = 0;
  bool confidence = false, temporary_artifact = false, missing_artifact = false;
};
struct JsonBytes {
  Bytes value;
  bool nil_slice = true;
};
struct Evidence {
  ByteString type;
  JsonBytes raw_json;
};
struct Causality {
  ByteString loader_origin = "UNKNOWN", active_caller = "IDLE",
             caller_file = "UNKNOWN";
  bool is_hook = false;
};
struct ClassEvidence {
  ByteString class_name, location;
  std::int64_t score = 0;
  bool has_unicode = false;
  Causality causality;
  std::vector<ByteString> flags;
  std::vector<Evidence> evidence;
  ByteString selected_rule;
  const Cluster *selected_context = nullptr;
};
struct Result {
  std::vector<ClassEvidence> evidence;
  std::vector<ByteString> unicode_class_names;
  ErrorWords error;
};

struct ReviewedStages {
  // Each method below binds to a readable implementation listed by
  // kStageBindings in java_complete_evidence_pipeline.cpp. Provider methods
  // keep the wiring readable without duplicating each reconstructed body.
  virtual std::pair<std::vector<ClassRecord>, ErrorWords>
  cached_hotspot_classes(std::uint32_t pid) = 0;
  virtual ArtifactInputs collect_process_artifacts(std::uint32_t pid) = 0;
  virtual void enrich_artifact_categories(const std::vector<ClassRecord> &,
                                          ArtifactInputs &) = 0;
  virtual std::vector<Cluster> build_clusters(const std::vector<ClassRecord> &,
                                              const ArtifactInputs &) = 0;
  virtual void attribute_mixin_handlers(const std::vector<ClassRecord> &,
                                        std::vector<Cluster> &) = 0;
  virtual void build_artifact_profiles(const std::vector<ClassRecord> &,
                                       const ArtifactInputs &,
                                       const std::vector<Cluster> &) = 0;
  virtual void prepare_global_rule_inputs(const std::vector<ClassRecord> &,
                                          const ArtifactInputs &,
                                          const std::vector<Cluster> &) = 0;
  virtual bool sdk_excluded_class(const ByteString &) = 0;
  virtual Cluster *cluster_for(const ClassRecord &, std::vector<Cluster> &) = 0;
  virtual ClassEvidence initial_evidence(const ClassRecord &,
                                         const Cluster &) = 0;
  virtual void apply_rule_group(std::size_t original_order_index,
                                const ClassRecord &, Cluster &,
                                ClassEvidence &) = 0;
  virtual void append_selected_context_evidence(const ClassRecord &,
                                                const Cluster &,
                                                ClassEvidence &) = 0;
  virtual std::vector<ByteString>
  collect_unicode_names(const std::vector<ClassRecord> &) = 0;
  virtual std::vector<ClassEvidence>
  select_representatives(std::vector<ClassEvidence> &) = 0;
};

Result collect_java_evidence(ReviewedStages &runtime, std::uint32_t pid);
} // namespace ocean::reconstructed::minecraft_java_complete_pipeline
