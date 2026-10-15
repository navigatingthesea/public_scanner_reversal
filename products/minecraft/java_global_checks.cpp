#include "../../session/session_types.hpp"
namespace ocean::reconstructed::minecraft_global_java_review {
// Purpose: perform two process-wide setup/checks before per-JVM analysis:
// report process names containing "weave" and attempt to enable
// SeDebugPrivilege for later process-memory reads.
struct ProcessNameRecord {
  ByteString name;
  std::int32_t pid;
}; // 3672320:24B
struct PrivilegeLuid {
  std::uint32_t low, high;
};
struct OnePrivilege {
  std::uint32_t count;
  PrivilegeLuid luid;
  std::uint32_t attributes;
};
struct GlobalJavaContracts : TextContracts {
  virtual Result<std::vector<ProcessNameRecord>>
  original_process_snapshot() = 0; // o3IRluv@1c0a740
  virtual void
  original_weave_process_diagnostic() = 0; // bpIXacf.func1/TYheK4ZApSl3
                                           // console/status side effect;
                                           // user-requested GUI/console
                                           // boundary
  virtual void append_debug(const std::vector<ByteString> &) = 0; // 572e8e0
  virtual Result<NativeHandle>
  original_open_process_token(GoUint process, std::uint32_t access) = 0;
  virtual void original_register_deferred_token_close(NativeHandle) = 0;
  virtual Result<PrivilegeLuid>
  original_lookup_privilege_value(const ByteString &name) = 0;
  virtual GoError original_adjust_one_privilege(NativeHandle, bool disable_all,
                                                const OnePrivilege &,
                                                std::uint32_t length,
                                                GoUint previous_state,
                                                GoUint return_length) = 0;
};
// Provider boundary (o3IRluv), retained from typed static review:
// CreateToolhelp32Snapshot
// flags=2 and pid=0; original PROCESSENTRY32W size 0x238 (568), PID at offset
// 8, and UTF-16 name at offset 44 with 260 code units. Process32First/Next
// error handling remains a contract. Return every name
// plus int32 PID, with no name filter here, then defers snapshot close.
// UTF-16/native/runtime
// and all enumeration edge cases remain contracts, not success dummy calls.
// bpIXacf@1c0a3c0: examines ALL process names; lower contains "weave".
// No extension, exact name, signature, path or game-PID association check.
// App emits Detect/WeaveProcess/ORIGINALname, with no PID in this row. Every
// matching record appends, including duplicates, before aggregate
// normalization.
void check_all_process_names_for_weave(GlobalJavaContracts &r) {
  const auto processes = r.original_process_snapshot();
  if (processes.error.present())
    return;
  for (const auto &process : processes.value) {
    if (r.to_lower(process.name).find("weave") == ByteString::npos)
      continue;
    r.original_weave_process_diagnostic();
    r.append_debug({"Detect", "WeaveProcess", process.name});
  }
}
// Recovered (c17f1SFdK@1c10700): privilege setup, not a snapshot collector.
// Open current-process pseudo-handle token with query+adjust access 0x28.
// Convert literal SeDebugPrivilege to UTF-16.
// LookupPrivilegeValueW(nullSystem,name,luid). One TOKEN_PRIVILEGES record
// The TOKEN_PRIVILEGES record has count=1 and attributes=2. The Adjust return
// is ignored. No proof of actual privilege
// granted; missing assignment/Win32 failures may continue silently. The setup
// runs before per-JVM native memory checks.
void attempt_enable_debug_privilege(GlobalJavaContracts &r) {
  const auto token = r.original_open_process_token(0xffffffffffffffffULL, 0x28);
  if (token.error.present())
    return;
  r.original_register_deferred_token_close(token.value);
  const auto luid = r.original_lookup_privilege_value("SeDebugPrivilege");
  if (luid.error.present())
    return;
  const OnePrivilege privilege{1, luid.value, 2};
  (void)r.original_adjust_one_privilege(token.value, false, privilege, 16, 0,
                                        0);
}
} // namespace ocean::reconstructed::minecraft_global_java_review
