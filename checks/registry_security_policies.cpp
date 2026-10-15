#include "../../common/review_contracts.hpp"
#include <array>
// Recovered behavior summary:
//   Input: Security-policy registry values, Windows edition/OEM strings, and three native security
//          booleans.
//   Gate: Applies the recovered exact integer predicates and ordered lowercase modified-Windows
//         substrings; presence-only checks remain presence-only.
//   Output: Appends the corresponding WARNINGS entries for every matching condition.
//   Failure: Each provider error suppresses only its own finding; keys close through the recovered
//            deferred boundary.

namespace ocean::reconstructed::shared_registry_security_review {
struct RegistrySecurityContracts : TextContracts {
 using Key=std::uint64_t;
 virtual Result<Key> original_open_key(std::uint64_t,const ByteString&,std::uint32_t)=0;
 virtual Result<GoUint> original_integer_value(Key,const ByteString&)=0;
 virtual Result<ByteString> original_string_value(Key,const ByteString&)=0;
 virtual void original_register_deferred_key_close(Key)=0;
 virtual void append_warning(const ByteString&)=0; //572e7a0 -> aggregate WARNINGS
 virtual void original_recovery_scope(const std::function<void()>&)=0;
 virtual Result<bool> original_memory_integrity_enabled()=0; //QoqhEaa@12b8040
 virtual Result<bool> original_secure_boot_enabled()=0; //DbQgpg2dboX_@12b8320
 virtual Result<bool> original_fast_boot_enabled()=0; //PEwOG2vkzZa@12b9b00
 virtual ByteString original_sprintf_modified_windows(const ByteString& label,const ByteString& field,const ByteString& value)=0;
};
// ZlDbsI9@12a24e0. The predicate is successful READ, not value==1.
// The recovered warning makes a broader claim than the actual condition.
void check_pca_policy_value(RegistrySecurityContracts& r) {
 r.original_recovery_scope([&] {
  const auto key=r.original_open_key(0x80000002,"SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat",0x20019);
  if(key.error.present()) return;
  r.original_register_deferred_key_close(key.value);
  const auto value=r.original_integer_value(key.value,"DisablePca");
  if(!value.error.present()) r.append_warning("Pca File logging disabled");
 });
}
// A7r0EG7c95jA@12a8c80. Exact entire uint64 value==1; no low32 truncation.
void check_superfetch_policy_value(RegistrySecurityContracts& r) {
  const auto key=r.original_open_key(
   0x80000002,
   "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
   0x20019);
 if(key.error.present()) return;
 r.original_register_deferred_key_close(key.value);
 const auto value=r.original_integer_value(key.value,"EnableSuperfetch");
 if(!value.error.present() && value.value==1) r.append_warning("Prefetch Run-logs disabled");
}
struct ModifiedWindowsMatch {
    const char* needle;
    const char* label;
};
constexpr std::array<ModifiedWindowsMatch,12> modified_windows={{
 {"kernelos","KernelOS"},{"kernel os","KernelOS"},
 {"atlasos","AtlasOS"},{"atlas os","AtlasOS"},{"revatmos","RevatmOS"},
 {"tiny11","Tiny11"},{"ghostspectre","Ghost Spectre"},{"ghost spectre","Ghost Spectre"},
 {"windowsxlite","Windows X-Lite"},{"x-lite","Windows X-Lite"},
 {"ameliorated","Windows AME"},{"ame ","Windows AME"}
}};
// nnqA3gY4A@12ba520. First byte-substring match on the lowercased value.
// No word boundary or exact-product-name requirement (catlasoskit matches).
const char* match_modified_windows(RegistrySecurityContracts& r,const ByteString& value) {
 const auto lower=r.to_lower(value);
 for(const auto& row:modified_windows) if(lower.find(row.needle)!=ByteString::npos) return row.label;
 return nullptr;
}
void check_modified_windows_field(
 RegistrySecurityContracts& r,RegistrySecurityContracts::Key key,
 const ByteString& field,const ByteString& display_field) {
 const auto value=r.original_string_value(key,field);
 if(value.error.present()) return;
 if(const auto label=match_modified_windows(r,value.value))
  r.append_warning(r.original_sprintf_modified_windows(label,display_field,value.value));
 // Captured output: "Running %s detected (ProductName: %s)", EditionID
 // counterpart and "Running %s detected (OEM %s: %s)". Values stay original.
}
// gYlchP1M4iZL@12ba600. Each key open is independent. Each failed read
// skips only that value. Closing all successful keys is deferred in Go order.
void check_uac_and_modified_windows_metadata(RegistrySecurityContracts& r) {
 const auto system=r.original_open_key(0x80000002,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",1);
 if(!system.error.present()) {
  r.original_register_deferred_key_close(system.value);
  const std::array<const char*,4> names={"EnableLUA","FilterAdministratorToken","PromptOnSecureDesktop","LocalAccountTokenFilterPolicy"};
  const std::array<GoUint,4> compared={0,0,0,1};
  const std::array<const char*,4> warnings={
   "Applications are running as administrator by default",
   "Administrator account is running without privilege restrictions",
   "Privilege elevation occurs without a secure confirmation prompt",
   "Local accounts are running with unrestricted administrative privileges"};
  for(std::size_t i=0;i<names.size();++i) {
   const auto value=r.original_integer_value(system.value,names[i]);
   if(!value.error.present() && value.value==compared[i]) r.append_warning(warnings[i]);
  }
 }
 const auto version=r.original_open_key(0x80000002,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",1);
 if(!version.error.present()) {
  r.original_register_deferred_key_close(version.value);
  check_modified_windows_field(r,version.value,"ProductName","ProductName");
  check_modified_windows_field(r,version.value,"EditionID","EditionID");
 }
 const auto oem=r.original_open_key(0x80000002,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation",1);
 if(!oem.error.present()) {
  r.original_register_deferred_key_close(oem.value);
  for(const auto field:{"Manufacturer","Model","SupportURL"})
   check_modified_windows_field(r,oem.value,field,ByteString("OEM ")+field);
 }
}
// XYFnooAj9@12b9fc0. All three native-provider error branches suppress
// their own warning and continue; the registry-policy helper runs afterward.
void check_shared_security_features(RegistrySecurityContracts& r) {
 const auto integrity=r.original_memory_integrity_enabled();
 if(!integrity.error.present() && !integrity.value) r.append_warning("Memory Integrity is disabled");
 const auto secure=r.original_secure_boot_enabled();
 if(!secure.error.present() && !secure.value) r.append_warning("Secure Boot is disabled");
 const auto fast=r.original_fast_boot_enabled();
 if(!fast.error.present() && fast.value) r.append_warning("Fast Boot is enabled");
 check_uac_and_modified_windows_metadata(r);
}
// Native helper identities from captured bindings: NtQuerySystemInformation,
// GetFirmwareEnvironmentVariableW, RegOpenKeyExW/RegQueryValueExW/RegCloseKey.
// Native provider contracts remain under separate review. Their names alone
// are not evidence that these calls execute successfully on every system.
// Evidence:21 registry fixtures (PCA stops in recovery after its core),7 full
// policy/matcher fixtures,14 modified-OS fixtures and8 wrapper bool/error
// fixtures. ASCII string models and intercepted registry/native/recovery
// contracts limit the proof. Review text only; never compiled/executed.

// QVUohz43oK@125dce0 and AAcXOJQI1iy@125aee0: successful integer
// READ alone triggers warning, including0,1,2,3 and uint64 wide value.
// Native registry type/error handling and recovery remain contracts.
void check_ngen_usage_log_value_presence(RegistrySecurityContracts& r) {
 r.original_recovery_scope([&] {
  const auto key=r.original_open_key(0x80000002,"SOFTWARE\\Microsoft\\.NETFramework",0x20019);
  if(key.error.present()) return;
  r.original_register_deferred_key_close(key.value);
  if(!r.original_integer_value(key.value,"NGenAssemblyUsageLog").error.present())
   r.append_warning("C# Apps run-log disabled");
 });
}
void check_activity_feed_value_presence(RegistrySecurityContracts& r) {
 r.original_recovery_scope([&] {
  const auto key=r.original_open_key(0x80000002,"SOFTWARE\\Policies\\Microsoft\\Windows\\System",0x20019);
  if(key.error.present()) return;
  r.original_register_deferred_key_close(key.value);
  if(!r.original_integer_value(key.value,"EnableActivityFeed").error.present())
   r.append_warning("ActivitiesCache.db logging disabled");
 });
}
// Yz45iqrL@125df80: successful string READ alone; empty autorun also warns.
// Content of autorun is not put in this warning by this check.
void check_command_processor_autorun_presence(RegistrySecurityContracts& r) {
 r.original_recovery_scope([&] {
  const auto key=r.original_open_key(0x80000002,"SOFTWARE\\Microsoft\\Command Processor",0x20019);
  if(key.error.present()) return;
  r.original_register_deferred_key_close(key.value);
  if(!r.original_string_value(key.value,"autorun").error.present())
   r.append_warning("Command Processor command active.");
 });
}
}
