#include "../../session/session_types.hpp"
#include <functional>
#include <unordered_map>
#include <unordered_set>

namespace ocean::reconstructed::minecraft_process_artifacts_review {
// Purpose: build the candidate JAR set used for class ownership and artifact
// attribution. Sources are open files, selected classpath arguments, gameDir
// mod folders, and IchOr's localModPath property.
using Word = std::uint64_t;
using OwnerMap = std::unordered_map<ByteString, ByteString>;
using ArtifactFeatures =
    std::unordered_map<ByteString, std::unordered_map<ByteString, bool>>;
struct Error {
  Word type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct ProcessResult {
  Word original_identity = 0;
  Error error;
};
struct OpenFile {
  ByteString path;
  std::uint64_t descriptor = 0;
}; // original24-byte row
struct FileList {
  std::vector<OpenFile> value;
  Error error;
};
struct Arguments {
  std::vector<ByteString> value;
  Error error;
};
struct DirEntry {
  bool present = false, is_directory = false;
  Error error;
};
struct Artifacts {
  OwnerMap class_owners;
  std::vector<ByteString> paths;
  ArtifactFeatures sensitive_categories;
  OwnerMap identifiers;
};
struct Contracts {
  virtual ProcessResult
  original_new_process_with_background_context(std::uint32_t) = 0;
  virtual FileList
  original_open_files_with_background_context(Word process) = 0;
  virtual Arguments
  original_cmdline_slice_with_background_context(Word process) = 0;
  virtual ByteString original_unicode_lowercase(const ByteString &) = 0;
  virtual bool original_unicode_equal_fold(const ByteString &,
                                           const ByteString &) = 0;
  virtual ByteString original_windows_extension(const ByteString &) = 0;
  virtual ByteString original_windows_join(const std::vector<ByteString> &) = 0;
  virtual std::vector<ByteString>
  original_windows_split_list(const ByteString &) = 0;
  virtual Error original_walk_dir(
      const ByteString &,
      const std::function<void(const ByteString &, const DirEntry &)> &) = 0;
  virtual void reviewed_archive_name_and_json_metadata(
      const ByteString &, OwnerMap &, ArtifactFeatures &,
      OwnerMap *) = 0; // java_jar_metadata_collection.cpp
};

ByteString trim_quote_ends(ByteString input) {
  while (!input.empty() && input.front() == '"')
    input.erase(0, 1);
  while (!input.empty() && input.back() == '"')
    input.pop_back();
  return input; // no whitespace trim
}
bool starts_with(const ByteString &text, const ByteString &prefix) {
  return text.compare(0, prefix.size(), prefix) == 0;
}

// Recovered (jCX.func1 @ 1e688a0): shared candidate callback; no existence/stat
// gate.
void collect_candidate(Contracts &runtime, Artifacts &result,
                       std::unordered_set<ByteString> &seen,
                       const ByteString &candidate) {
  auto path = trim_quote_ends(candidate);
  if (starts_with(path, "\\\\?\\"))
    path.erase(0, 4);
  if (!runtime.original_unicode_equal_fold(
          runtime.original_windows_extension(path), ".jar"))
    return;
  if (!seen.insert(runtime.original_unicode_lowercase(path)).second)
    return;
  result.paths.push_back(
      path); // first spelling, retained even if ZIP Open fails
  runtime.reviewed_archive_name_and_json_metadata(path, result.class_owners,
                                                  result.sensitive_categories,
                                                  &result.identifiers);
}

// Recovered (aGSGBH @ 1e68d40 and func1 @ 1e68dc0): walk errors are ignored and
// the callback returns nil, including errored/missing/directory entries.
void collect_directory(Contracts &runtime, Artifacts &result,
                       std::unordered_set<ByteString> &seen,
                       const ByteString &root) {
  if (root.empty())
    return;
  runtime.original_walk_dir(
      root, [&](const ByteString &path, const DirEntry &entry) {
        if (entry.error.present() || !entry.present || entry.is_directory)
          return;
        if (runtime.original_unicode_equal_fold(
                runtime.original_windows_extension(path), ".jar"))
          collect_candidate(runtime, result, seen, path);
      });
}

// Recovered (gTaCLViH5 @ 1e68ae0): both directories in order, not just mods.
void collect_game_directory(Contracts &runtime, Artifacts &result,
                            std::unordered_set<ByteString> &seen,
                            const ByteString &root) {
  if (root.empty())
    return;
  const auto processed =
      runtime.original_windows_join({".fabric", "processedMods"});
  for (const auto &relative : {ByteString{"mods"}, processed})
    collect_directory(runtime, result, seen,
                      runtime.original_windows_join({root, relative}));
}

// Recovered (jCXTiSFW3 @ 1e66f60): initialized maps/non-nil empty paths even on
// errors.
Artifacts collect_process_artifacts(Contracts &runtime, std::uint32_t pid) {
  Artifacts result;
  std::unordered_set<ByteString> seen;
  const auto process =
      runtime.original_new_process_with_background_context(pid);
  if (process.error.present())
    return result;
  const auto files = runtime.original_open_files_with_background_context(
      process.original_identity);
  if (!files.error.present())
    for (const auto &file : files.value)
      collect_candidate(runtime, result, seen, file.path);

  const auto arguments = runtime.original_cmdline_slice_with_background_context(
      process.original_identity);
  if (arguments.error.present())
    return result;
  const auto &args = arguments.value;
  for (std::size_t index = 0; index < args.size(); ++index) {
    const auto &arg = args[index];
    if (arg == "-cp" || arg == "-classpath" || arg == "--class-path") {
      if (index + 1 == args.size())
        continue;
      for (const auto &candidate :
           runtime.original_windows_split_list(args[++index]))
        collect_candidate(runtime, result, seen, candidate);
    } else if (arg == "--gameDir") {
      if (index + 1 < args.size())
        collect_game_directory(runtime, result, seen, args[++index]);
    } else if (starts_with(arg, "-Dichor.fabric.localModPath=")) {
      collect_directory(
          runtime, result, seen,
          arg.substr(ByteString{"-Dichor.fabric.localModPath="}.size()));
    } else if (starts_with(arg, "-Djava.class.path=")) {
      for (const auto &candidate : runtime.original_windows_split_list(
               arg.substr(ByteString{"-Djava.class.path="}.size())))
        collect_candidate(runtime, result, seen, candidate);
    }
  }
  return result;
}
// Plain paths, -jar, -cp=..., differently-cased flags/properties and
// --gameDir=... are ignored. Consumed next arguments are not parsed as flags.
// Game/local-mod directory values keep quotes; classpath SplitList and
// candidate quote stripping are separate. No wildcard expansion for *.jar.
// Root/native/JSON/Unicode provider behavior remains the declared contracts.
// Evidence: 65 process argument/open-file paths and 15 walk-controller paths.
// No sample/native filesystem/process/C++ execution or source compilation.
} // namespace ocean::reconstructed::minecraft_process_artifacts_review
