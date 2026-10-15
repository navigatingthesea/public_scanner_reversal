#include "../../session/session_types.hpp"
#include <algorithm>
#include <memory>
#include <unordered_map>

namespace ocean::reconstructed::minecraft_jar_metadata_review {
// Purpose: index class ownership and selected JSON metadata from candidate JAR
// archives. It records member names and identifiers; it does not execute JARs
// or parse class bytecode here.
using Word = std::uint64_t;
using OwnerMap = std::unordered_map<ByteString, ByteString>;
using Categories = std::unordered_map<ByteString, bool>;
using ArtifactFeatures = std::unordered_map<ByteString, Categories>;
struct Error {
  Word type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct Member {
  Word original_identity = 0;
  ByteString name;
  Word uncompressed_size = 0;
};
struct Archive {
  Word original_identity = 0;
  std::vector<Member> entries;
};
struct OpenArchive {
  std::shared_ptr<Archive> value;
  Error error;
};
struct OpenMember {
  Word reader_identity = 0;
  Error error;
};
struct ReadBytes {
  std::vector<std::uint8_t> value;
  Error error;
};
struct ModId {
  ByteString id;
};
struct MixinConfiguration {
  ByteString package, compatibility_level, min_version;
  std::vector<ByteString> mixins, client, server;
  std::vector<std::uint8_t> injectors_raw_json;
};
struct Contracts {
  virtual OpenArchive original_open_zip(const ByteString &) = 0;
  virtual Error original_close_zip(Archive &) = 0;
  virtual OpenMember original_open_member(const Member &) = 0;
  virtual ReadBytes original_read_all_through_limited_reader(Word reader,
                                                             Word limit) = 0;
  virtual Error original_close_member(Word reader) = 0;
  virtual Error original_json_unmarshal_id(const std::vector<std::uint8_t> &,
                                           ModId &) = 0;
  virtual Error original_json_unmarshal_mixin(const std::vector<std::uint8_t> &,
                                              MixinConfiguration &) = 0;
  virtual ByteString original_unicode_lowercase(const ByteString &) = 0;
  virtual bool original_unicode_equal_fold(const ByteString &,
                                           const ByteString &) = 0;
  virtual bool original_parse_go_int_decimal(const ByteString &) = 0;
  virtual ByteString original_path_extension(const ByteString &) = 0;
  virtual void reviewed_associate_id(OwnerMap *, const ByteString &,
                                     const ByteString &) = 0;
  virtual void reviewed_associate_mixin_alias(OwnerMap *, const ByteString &,
                                              const ByteString &) = 0;
  virtual std::vector<ByteString>
  reviewed_mixin_sensitive_categories(const ByteString &) = 0;
};

bool ends_with(const ByteString &input, const ByteString &suffix) {
  return input.size() >= suffix.size() &&
         input.compare(input.size() - suffix.size(), suffix.size(), suffix) ==
             0;
}
ByteString last_dot_component(const ByteString &name) {
  const auto dot = name.rfind('.');
  return dot == ByteString::npos ? name : name.substr(dot + 1);
}

// dRUvUJa @ 1e6a100: one multi-release prefix is removed on successful Atoi.
// No version >=9 or positive-number restriction: 0, -1, +1 are accepted.
// Signed Go-int overflow, whitespace, non-ASCII digits or absent slash retain
// the original name. This function does not strip a leading slash itself.
ByteString normalize_member_name(Contracts &runtime, const ByteString &name) {
  const ByteString prefix = "META-INF/versions/";
  if (name.compare(0, prefix.size(), prefix) != 0)
    return name;
  const auto slash = name.find('/', prefix.size());
  if (slash == ByteString::npos)
    return name;
  const auto version = name.substr(prefix.size(), slash - prefix.size());
  if (!runtime.original_parse_go_int_decimal(version))
    return name;
  return name.substr(slash + 1);
}

// eXo4EFbTVn @ 1e69460. Every .json entry is considered, without checking
// a specific member filename. Archive metadata and actual read both cap 1MiB.
void collect_json_metadata(Contracts &runtime, const ByteString &artifact,
                           const Member &member, OwnerMap *identifiers) {
  constexpr Word limit = 1048576;
  if (!identifiers || member.uncompressed_size > limit)
    return;
  const auto opened = runtime.original_open_member(member);
  if (opened.error.present())
    return;
  const auto read = runtime.original_read_all_through_limited_reader(
      opened.reader_identity, limit);
  if (read.error.present() || read.value.empty()) {
    runtime.original_close_member(opened.reader_identity);
    return;
  }
  ModId id;
  if (!runtime.original_json_unmarshal_id(read.value, id).present())
    runtime.reviewed_associate_id(identifiers, id.id, artifact);

  // ID association is preserved if the second parse fails or is not Mixin
  // shaped. Both parsers receive the same limited byte slice.
  MixinConfiguration config;
  const auto parse = runtime.original_json_unmarshal_mixin(read.value, config);
  if (!parse.present() && !config.package.empty() &&
      (!config.compatibility_level.empty() || !config.min_version.empty() ||
       !config.injectors_raw_json.empty())) {
    for (const auto *list : {&config.mixins, &config.client, &config.server})
      for (const auto &name : *list)
        runtime.reviewed_associate_mixin_alias(
            identifiers, last_dot_component(name), artifact);
  }
  // Close errors ignored on every normal path after a successful Open.
  // Panic cleanup remains the original Go defer contract, not C++ execution.
  runtime.original_close_member(opened.reader_identity);
}

// Recovered (beaTPxgwlr0 @ 1e68f00): class names and JSON metadata, never class
// bytecode.
void collect_archive_names(Contracts &runtime, const ByteString &artifact,
                           OwnerMap &class_owners, ArtifactFeatures &features,
                           OwnerMap *identifiers) {
  const auto opened = runtime.original_open_zip(artifact);
  if (opened.error.present())
    return;
  for (const auto &member : opened.value->entries) {
    ByteString name = member.name;
    if (!name.empty() && name.front() == '/')
      name.erase(0, 1); // one only
    const auto lower = runtime.original_unicode_lowercase(name);
    if (ends_with(lower, ".json")) {
      collect_json_metadata(runtime, artifact, member, identifiers);
      continue;
    }
    if (!ends_with(lower, ".class"))
      continue;
    name = normalize_member_name(runtime, name);
    const auto extension = runtime.original_path_extension(name);
    name.resize(name.size() - extension.size());
    std::replace(name.begin(), name.end(), '/', '.'); // backslash unchanged
    if (name.empty())
      continue;
    const auto existing = class_owners.find(name);
    if (existing != class_owners.end() &&
        !runtime.original_unicode_equal_fold(existing->second, artifact))
      class_owners[name].clear();
    else
      class_owners[name] = artifact;
    for (const auto &category :
         runtime.reviewed_mixin_sensitive_categories(name))
      features[artifact][category] = true;
  }
  runtime.original_close_zip(*opened.value); // ignored error, original defer
}
// Evidence: 23 JSON-controller, 16 entry-index, and 30 normalizer paths.
// JSON decoding/type behavior, ZIP IO and Unicode/runtime helpers are explicit
// contracts. Invalid RawMessage contents are not guessed from field presence.
// These bodies feed artifact profiles and the rule pipeline; they do not
// directly emit warnings or reports. Review only; never compile/run this source
// or sample.
} // namespace ocean::reconstructed::minecraft_jar_metadata_review
