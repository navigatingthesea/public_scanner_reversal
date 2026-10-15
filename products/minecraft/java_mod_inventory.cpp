#include "../../session/session_types.hpp"
#include <set>
namespace ocean::reconstructed::minecraft_mod_review {
struct ProcessRef { std::uint64_t original_pointer; };
struct OpenFile { ByteString path; };
struct FileInfoRef { std::uint64_t itab,data; };
struct ModContracts : TextContracts {
 virtual const std::vector<GoInt>& selected_java_pids()=0; // global57321c0/c8/d0
 virtual Result<ProcessRef> original_new_process(std::int32_t)=0; // wT5Owez4.T9FK3jXcW
 virtual Result<ByteString> original_command_line(ProcessRef)=0;
 virtual Result<std::vector<OpenFile>> original_open_files(ProcessRef)=0;
 virtual ByteString original_windows_clean(const ByteString&)=0; //1d5e20
 virtual ByteString original_windows_dir(const ByteString&)=0; //1d6ce0
 virtual ByteString original_path_extension(const ByteString&)=0;
 virtual Result<FileInfoRef> original_stat(const ByteString&)=0;
 virtual bool original_file_info_is_dir(FileInfoRef)=0;
 virtual GoInt original_file_info_size(FileInfoRef)=0;
 virtual void set_last_mod_directory(const ByteString&)=0; //5732238/40; last accepted file wins
 virtual Result<ByteString> original_read_entire_file(const ByteString&)=0;
 virtual ByteString original_trim_right(const ByteString&,const ByteString& cutset)=0; //247240
 virtual ByteString original_stream_file_sha1_lower_hex_or_empty(const ByteString&)=0; //1c46500
 virtual ByteString original_sprintf_mod_row(const ByteString& path,GoInt size,
                                             const ByteString& host_url,
                                             const ByteString& sha1)=0;
 virtual void append_internal_warning(const ByteString&)=0; //572e7a0 -> aggregate WARNINGS
 virtual void original_timed_recovery_scope(const std::function<void()>&)=0;
};
// Recovered: BFgM3L.SlMjYHrkjsFM @ 0x1b15ea0. The preliminary open-file test is
// CASE SENSITIVE and looks for a substring anywhere, not a file extension.
// It constructs its own process object and queries its open files BEFORE the
// collector constructs a second process object and queries the files again.
bool has_lowercase_jar_in_open_file_name(ModContracts& r,std::int32_t pid) {
 const auto process=r.original_new_process(pid);
 if(process.error.present()) return false;
 const auto files=r.original_open_files(process.value);
 if(files.error.present()) return false;
 for(const auto& file:files.value) if(file.path.find(".jar")!=ByteString::npos) return true;
 return false;
}
// Recovered: gKUdZHIZpX.yx4AEpYj1 @ 0x1c46820 removes precisely the four-byte long-path
// prefix, then apply the original Windows filepath.Clean implementation.
ByteString clean_open_file_path(ModContracts& r,ByteString path) {
 if(path.compare(0,4,"\\\\?\\")==0) path.erase(0,4);
 return r.original_windows_clean(path);
}
// Recovered: gKUdZHIZpX.lu0mlBGhhj @ 0x1c46880 accepts the exact HostUrl= prefix;
// ReferrerUrl is
// ignored. An empty FIRST HostUrl value is returned as empty, not "None".
ByteString download_source_from_zone_identifier(ModContracts& r,const ByteString& ads_path) {
 const auto data=r.original_read_entire_file(ads_path);
 if(data.error.present()) return "None";
 std::size_t start=0;
 while(start<=data.value.size()) {
  const auto end=data.value.find('\n',start);
  const auto line=r.original_trim_right(data.value.substr(start,end==ByteString::npos?ByteString::npos:end-start),"\r");
  if(line.compare(0,8,"HostUrl=")==0) return r.trim_space(line.substr(8));
  if(end==ByteString::npos) break;
  start=end+1;
 }
 return "None";
}
// Recovered: gKUdZHIZpX.Kb98QVd @ 0x1c445a0. Collector core under explicit Go/runtime,
// process, filesystem, formatting and timing/recovery contracts. No syscall
// implementation is provided. Deduplication is global to this invocation and
// uses the lowercased cleaned full path. The output keeps the case-preserved
// cleaned path rather than the deduplication key.
StringList collect_java_mod_inventory(ModContracts& r) {
 StringList result;
 r.original_timed_recovery_scope([&] {
  std::set<ByteString> seen;
  for(const auto wide_pid:r.selected_java_pids()) {
   const auto pid=static_cast<std::int32_t>(static_cast<std::uint32_t>(wide_pid));
   if(pid==0) continue;
   if(!has_lowercase_jar_in_open_file_name(r,pid)) continue;
   const auto process=r.original_new_process(pid);
   if(process.error.present()) continue;
   const auto command=r.original_command_line(process.value);
   if(command.error.present()) continue;
    // Recovered: Lunar override paths are eligible only when the command line
    // contains the case-sensitive substring "lunar.genesis".
    const bool lunar=command.value.find("lunar.genesis")!=ByteString::npos;
   const auto files=r.original_open_files(process.value);
   if(files.error.present()) continue;
   bool accepted_override=false;
   for(const auto& file:files.value) {
    const auto path=clean_open_file_path(r,file.path);
    auto normalized=path;
    for(auto& ch:normalized) if(ch=='/') ch='\\'; // original strings.Replace(...,-1)
    normalized=r.to_lower(normalized);
    // Recovered path gates: a normalized path contains mods, mod_cache, or
    // user-mods; Lunar additionally permits any path containing "\\overrides".
    const bool regular_mod=normalized.find("\\mods\\")!=ByteString::npos ||
      normalized.find("\\mod_cache\\")!=ByteString::npos || normalized.find("\\user-mods\\")!=ByteString::npos;
    const bool override_path=lunar && normalized.find("\\overrides")!=ByteString::npos;
    if(!regular_mod && !override_path) continue;
    if(!r.equal_fold(r.original_path_extension(path),".jar")) continue;
    const auto key=r.to_lower(r.original_windows_clean(path));
    if(seen.count(key)) continue;
    const auto info=r.original_stat(path);
    if(info.error.present() || r.original_file_info_is_dir(info.value)) continue;
    // Recovered: deduplication happens only after successful stat and non-directory
    // validation, so a failed first occurrence does not suppress a later one.
    seen.insert(key);
    r.set_last_mod_directory(r.original_windows_dir(path));
    const auto url=download_source_from_zone_identifier(r,path+":Zone.Identifier");
    const auto size=r.original_file_info_size(info.value);
    const auto sha1=r.original_stream_file_sha1_lower_hex_or_empty(path);
    result.has_backing_storage=true;
    // Recovered row format: "%s:::%d:::%s:::%s". It contains path, size,
    // Zone.Identifier HostUrl, and SHA-1. File bytes and timestamps are omitted.
    // included in this row. Empty hash/URL are retained.
    result.items.push_back(r.original_sprintf_mod_row(path,size,url,sha1));
    accepted_override=accepted_override || override_path;
   }
   if(accepted_override) r.append_internal_warning("User has active Override Lunar Mods");
  }
 });
 return result;
}
// Controller worker31@1f00620 boxes the returned []string at572b9a0/a8.
// Aggregate GoFq@1f00ec0 inserts that exact interface into MODS at1f05953.
// Internal warnings572e7a0 are merged with572e5e0 and HCZ3Ed-transformed
// before WARNINGS insertion at1f05799. Transform semantics reviewed separately.
// SHA-1 identity: five-word standard IV; "sha\x01" state serialization;
// standard SHA-1 round constants and SHA1RNDS4/SHA1MSG instructions.
// Evidence: 17 original core fixtures, eight original ADS parser fixtures and static
// hash/body/caller/wire reads. These do not prove provider internals or every
// Unresolved: provider internals and every panic/race/recovery path are not proved.
// Review text only; never compiled or executed.
}
