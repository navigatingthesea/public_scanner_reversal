#include "java_agent_inputs.hpp"
namespace ocean::reconstructed::minecraft_agent_input_review {
struct ProfileDirectoryEntry {ByteString name;bool is_directory;};
struct SecondaryJavaContracts : AgentInputContracts {
 virtual ByteString original_windows_dir(const ByteString&)=0;
 virtual ByteString original_windows_join(const std::vector<ByteString>&)=0;
 virtual Result<std::vector<ProfileDirectoryEntry>> original_read_directory(const ByteString&)=0;
 virtual Result<bool> original_stat_is_directory(const ByteString&)=0;
 virtual void append_warning(const ByteString&)=0;
 virtual void append_variable_length_debug_row(const std::vector<ByteString>&)=0;
 virtual std::vector<AgentProcessRecord> original_completed_agent_process_collector()=0; //eEvOCTP@1c37f60
 virtual void original_bpIXacf_check()=0; //1c0a3c0, core reviewed in java_global_checks.cpp; snapshot provider contract
 virtual void original_named_pipe_check()=0; //lNiksAj@1c0ab80
 virtual void original_debug_privilege_setup()=0; //c17f1SFdK@1c10700, reviewed in java_global_checks.cpp
 // qctTAL5dYbB @ 0x1c0f3a0.
 virtual void original_per_jvm_native_inspection(const ByteString& name,
                                                 std::int32_t pid,
                                                 std::uint8_t agent_options_present)=0;
};
// Recovered: g6OpadzM @ 0x1c09c80 scans the parent of USERPROFILE, not a literal
// C:\Users path. For every child profile directory it checks whether .weave is
// also a directory.
// Reads every directory entry under that parent, then stats <entry>/.weave.
// It requires both the profile entry and .weave target to be directories.
// Enumerates .weave/mods after a directory match; no contents, signatures,
// active process or loader state is checked here.
void check_weave_directories_across_profiles(SecondaryJavaContracts& r) {
 const auto profile=r.original_getenv("USERPROFILE");
 if(profile.empty()) return;
 const auto parent=r.original_windows_dir(profile);
 const auto entries=r.original_read_directory(parent);
 if(entries.error.present()) return;
 for(const auto& entry:entries.value) {
  if(!entry.is_directory) continue;
  const auto path=r.original_windows_join({parent,entry.name,".weave"});
  const auto directory=r.original_stat_is_directory(path);
  if(directory.error.present() || !directory.value) continue;
  r.append_warning("Weave Cheat Loader:::On Disk:::.:::Weave folder:::Folder: "+path);
  r.append_variable_length_debug_row({"Warning","WeaveFolder",path});
   // Recovered continuation @ 0x1c09c80: every nondirectory entry in
   // .weave/mods produces a warning.
  // The label says "Mod Jar" even for readme.txt. No extension/content/hash
  // test is present. Listing error preserves the folder warning above.
  const auto mods_directory=r.original_windows_join({path,"mods"});
  const auto mods=r.original_read_directory(mods_directory);
  if(mods.error.present()) continue;
  for(const auto& mod:mods.value) {
   if(mod.is_directory) continue;
   const auto mod_path=r.original_windows_join({mods_directory,mod.name});
   r.append_warning("Weave Cheat Loader:::Mod Jar:::.:::Weave mods:::Jar: "+mod_path);
  }

 }
}
// Recovered: w1_B4CWE9od4 @ 0x1c34680 checks four environment variables for
// -javaagent, -agentpath, or -agentlib after lowercasing. It returns only a bool;
// this helper does not record the full variable values.
// hZYi8ltydAg separately collects those full values into JVMEnvAgent rows.
bool environment_contains_agent_options(SecondaryJavaContracts& r) {
 for(const auto name:{"JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS","JAVA_OPTS"}) {
  const auto value=r.original_getenv(name);
  if(value.empty()) continue;
  const auto lower=r.to_lower(value);
  if(lower.find("-javaagent")!=ByteString::npos ||
     lower.find("-agentpath")!=ByteString::npos ||
     lower.find("-agentlib")!=ByteString::npos) return true;
 }
 return false;
}
// Recovered: ti1wTaar @ 0x1c34f20. Exact substring choices differ from the
// environment gate: three options require ':'; -xrun is a fourth alternative.
bool command_contains_native_inspection_options(SecondaryJavaContracts& r,const ByteString& command) {
 const auto lower=r.to_lower(command);
  return lower.find("-javaagent:")!=ByteString::npos ||
   lower.find("-agentpath:")!=ByteString::npos ||
   lower.find("-agentlib:")!=ByteString::npos ||
   lower.find("-xrun")!=ByteString::npos;
}
// Recovered: TSCHoF @ 0x1c0ffe0 / controller worker 28. Four system checks run before the
// environment gate and all-process enumeration. Native per-process inspection
// only accepts exact lowercase java.exe/javaw.exe names, even though eEvOCTP's
// broader candidate predicate can include renamed processes.
void run_secondary_minecraft_java_checks(SecondaryJavaContracts& r) {
 r.original_timed_recovery_scope([&] {
  check_weave_directories_across_profiles(r);
  r.original_bpIXacf_check();
  r.original_named_pipe_check();
  r.original_debug_privilege_setup();
  const bool from_environment=environment_contains_agent_options(r);
  const auto records=r.original_completed_agent_process_collector();
  for(const auto& record:records) {
   const auto name=r.to_lower(record.name);
   if(name!="java.exe" && name!="javaw.exe") continue;
   const bool from_command=command_contains_native_inspection_options(r,record.command_line);
   r.original_per_jvm_native_inspection(
       record.name,
       static_cast<std::int32_t>(static_cast<std::uint32_t>(record.pid)),
       static_cast<std::uint8_t>(from_environment || from_command));
  }
 });
}
// Recovered: only the low byte of ti1wTaar's bool is meaningful. Original fixtures retain
// e.g. RAX43e10f00 for false and43e10f01 for true: upper register bits can be
// decoder artifacts. qctTAL5dYbB takes a one-byte fourth argument. Do not turn
// dirty upper bits into an integer truth test.
// Evidence:6 profile-directory,5 dispatcher and24 option-gate core fixtures.
// Named-pipe/native/global-check cores are reviewed in their separate files.
// Unresolved: snapshot provider, runtime/recovery, named-pipe implementation,
// native per-JVM inspection, and diagnostic logging remain explicit contracts or
// are mapped in their separate files.
// Review text only; never compiled or executed.
// Recovered correction: ten full-flow fixtures proved that duplicate file names
// append duplicate WARNINGS before final normalization. Mod-entry warnings do
// not add a corresponding DEBUG_DETECTIONS row.
}
