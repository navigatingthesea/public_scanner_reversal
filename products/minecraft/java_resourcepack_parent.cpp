#include "../../session/session_types.hpp"
#include <functional>
#include <optional>
namespace ocean::reconstructed::resourcepack_parent_review {
// Purpose: enumerate the default .minecraft/resourcepacks directory, collect
// metadata with capacity-five workers, then run texture/blacklist analysis
// with a second capacity-five worker pool.
struct ErrorWords {
  std::uint64_t type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct TextResult {
  ByteString value;
  ErrorWords error;
};
struct ListedFileInfo {
  std::uint64_t original_itab = 0, original_data = 0;
};
struct Listing {
  std::vector<ListedFileInfo> entries;
  ErrorWords error;
};
struct CITRecord {
  ByteString pack_name;
  std::vector<ByteString> items, property_paths;
};
struct Metadata {
  ByteString pack_name, logo;
  std::vector<ByteString> file_names;
  std::uint32_t shared_icon_crc = 0;
  std::optional<CITRecord> cit;
};
struct PackReport {
  std::uint64_t opaque_reviewed_144byte_record = 0;
};
struct Statistics { // logical layout of captured 136-byte type3772ac0
  GoInt processed_metadata_count = 0; // 0
  std::vector<PackReport> detected;   // 8
  std::vector<CITRecord> cit;         // 32
  std::vector<ByteString> names_only; // 56
  std::vector<PackReport> suspected;  // 80
  // Unresolved: no role was recoverable for this slice at offset 104 because
  // all preserved fixtures left it empty.
  std::vector<ByteString> unresolved_field_104;
  GoInt elapsed_nanoseconds = 0; // 128
};
struct Result {
  std::optional<Statistics> value;
  ErrorWords error;
};
struct ParentContracts {
  virtual TextResult
  original_windows_user_home_dir() = 0; // nonempty USERPROFILE reviewed
  virtual ByteString
  original_join_resourcepack_root(const ByteString &home) = 0;
  // Join components AppData,Roaming,.minecraft,resourcepacks, verified earlier.
  virtual ErrorWords original_stat_error(const ByteString &) = 0;
  virtual bool original_is_not_exist(ErrorWords) = 0;
  virtual ErrorWords original_format_home_error(ErrorWords) = 0;
  virtual ErrorWords original_format_missing_root_error(const ByteString &) = 0;
  virtual ErrorWords original_format_listing_error(ErrorWords) = 0;
  virtual Listing original_read_directory_file_infos(const ByteString &) = 0;
  virtual std::uint64_t original_new_reviewed_texture_analyzer() = 0;
  virtual GoInt original_start_time_token() = 0;
  virtual GoInt original_elapsed_nanoseconds(GoInt) = 0;
  virtual std::optional<Metadata>
  original_inspect_metadata(const ByteString &root, ListedFileInfo) = 0;
  virtual void original_with_metadata_mutex(const std::function<void()> &) = 0;
  virtual void original_metadata_waitgroup_add_one() = 0;
  virtual void original_metadata_acquire_slot() = 0;
  virtual void original_start_metadata_job(const std::function<void()> &) = 0;
  // These names denote two separate capacity-5 channels.
  virtual void original_make_metadata_slots_capacity_five() = 0;
  virtual void original_wait_metadata_jobs() = 0;
  virtual void original_metadata_release_slot() = 0;
  virtual void original_metadata_waitgroup_done() = 0;
  virtual void original_metadata_worker_defer_scope(
      const std::function<void()> &body,
      const std::function<void()> &release_then_done) = 0;
  virtual void original_make_analysis_slots_capacity_five() = 0;
  virtual void original_analysis_waitgroup_add_one() = 0;
  virtual void original_analysis_acquire_slot() = 0;
  virtual void original_start_analysis_job(const std::function<void()> &) = 0;
  virtual void original_wait_analysis_jobs() = 0;
  // func7 controls reviewed separately in java_texture_analysis.cpp. Mutex,
  // slot/defer/done behavior and genuine concurrency remain runtime contracts.
  virtual void original_reviewed_analysis_worker(const ByteString &root,
                                                 std::uint64_t analyzer,
                                                 const Metadata &,
                                                 Statistics &shared) = 0;
};
// Recovered (Nl.func6@1c59f40): only non-nil metadata appends. The whole
// 72-byte record is copied under a mutex. Normal cleanup order: release channel
// slot, then WaitGroup Add(-1). Fast mutex path +nil/append/grow/cleanup
// original fixtures returned.
void metadata_job(ParentContracts &r, const ByteString &root,
                  ListedFileInfo info, std::vector<Metadata> &shared) {
  r.original_metadata_worker_defer_scope(
      [&] {
        const auto value = r.original_inspect_metadata(root, info);
        if (value)
          r.original_with_metadata_mutex([&] { shared.push_back(*value); });
      },
      [&] {
        r.original_metadata_release_slot();
        r.original_metadata_waitgroup_done();
      });
}
// Recovered (NlLamvI686Y@1c58300): logical C++ vectors do not recreate Go
// nil/backing storage distinctions or object layout. Empty original output
// slices have non-nil zerobase pointers; captured fixtures do not prove all
// marshaler paths.
Result inspect_default_resourcepacks(ParentContracts &r) {
  const auto start = r.original_start_time_token();
  const auto home = r.original_windows_user_home_dir();
  if (home.error.present())
    return {std::nullopt, r.original_format_home_error(home.error)};
  const auto root = r.original_join_resourcepack_root(home.value);
  const auto stat_error = r.original_stat_error(root);
  if (r.original_is_not_exist(stat_error))
    return {std::nullopt, r.original_format_missing_root_error(root)};
  // Other Stat errors are not an early return here. Directory listing follows.
  const auto analyzer = r.original_new_reviewed_texture_analyzer();
  const auto listed = r.original_read_directory_file_infos(root);
  if (listed.error.present())
    return {std::nullopt, r.original_format_listing_error(listed.error)};
  std::vector<Metadata> collected;
  Statistics out;
  r.original_make_metadata_slots_capacity_five();
  for (const auto info : listed.entries) {
    // NO extension/directory/product filter in this loop. Every returned entry
    // is submitted to the separately reviewed metadata helper, even plain
    // files.
    r.original_metadata_waitgroup_add_one();
    r.original_metadata_acquire_slot();
    r.original_start_metadata_job(
        [&, info] { metadata_job(r, root, info, collected); });
  }
  r.original_wait_metadata_jobs();
  // Collection order depends on concurrent worker completion; no sort/dedup
  // of metadata/CIT occurs here. Copy every non-nil CIT record before phase 2.
  for (const auto &metadata : collected)
    if (metadata.cit)
      out.cit.push_back(*metadata.cit);
  r.original_make_analysis_slots_capacity_five();
  for (const auto metadata : collected) {
    r.original_analysis_waitgroup_add_one();
    r.original_analysis_acquire_slot();
    ++out.processed_metadata_count; // increments before analysis, independent
                                    // of detection
    r.original_start_analysis_job([&, metadata] {
      r.original_reviewed_analysis_worker(root, analyzer, metadata, out);
    });
  }
  r.original_wait_analysis_jobs();
  out.elapsed_nanoseconds = r.original_elapsed_nanoseconds(start);
  return {out, {}};
}
// Thus no live --gameDir/profile enumeration is used for THIS root path:
// default USERPROFILE/AppData/Roaming/.minecraft/resourcepacks only. Other
// Minecraft collectors have different path/process scopes. Parent scheduling,
// metadata processing, texture/CIT predicates and report transport are distinct
// reviewed levels, not one fixture proof of every real execution/exception
// path.
} // namespace ocean::reconstructed::resourcepack_parent_review
