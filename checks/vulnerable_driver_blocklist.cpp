#include "../../common/review_contracts.hpp"
// Recovered behavior summary:
//   Input: The vulnerable-driver blocklist registry integer and previously collected Windows
//          version text.
//   Gate: A successful value different from exactly uint64 1 enters the recovered version substring
//         test.
//   Output: Appends the vulnerable-driver-blocklist warning on the matching version path.
//   Failure: Open/query failures and value 1 suppress output; no driver loading or policy change is
//            performed.

namespace ocean::reconstructed::shared_check_review {
struct DriverBlocklistContracts {
 using Key=std::uint64_t;
 virtual ~DriverBlocklistContracts()=default;
 virtual Result<Key> original_open_registry_key(std::uint64_t root,const ByteString& path,std::uint32_t access)=0;
 virtual Result<GoUint> original_get_integer_value(Key,const ByteString& value_name)=0;
 virtual void original_register_deferred_key_close(Key)=0;
 virtual ByteString shared_windows_version()=0; // global572b820/828
 virtual void append_internal_result(std::uint64_t slice_global_rva,const ByteString&)=0;
 // Original `VULN_DRIVER` timing/recovery/defer wrapper. Timings, locks,
 // formatter and final scheduling remain dependencies, not successful stubs.
 virtual void original_timed_recovery_scope(const ByteString& label,const std::function<void()>&)=0;
};
// vJtYm8.TWgWU6LhXgbp@18a5d20. A successful value different from ONE
// triggers the version test, including a wide QWORD value whose low32bits=1.
// It checks a case-sensitive substring in the previously collected version.
// Open/query errors and value1 produce no result; it does not prove who changed
// the registry value, or that the change occurred during this boot/session.
void check_vulnerable_driver_blocklist(DriverBlocklistContracts& r) {
 r.original_timed_recovery_scope("VULN_DRIVER",[&] {
  const auto key=r.original_open_registry_key(0x80000002ULL,"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",1);
  if(key.error.present()) return;
  r.original_register_deferred_key_close(key.value);
  const auto value=r.original_get_integer_value(key.value,"VulnerableDriverBlocklistEnable");
  if(value.error.present() || value.value==1) return;
  if(r.shared_windows_version().find("Windows 11")==ByteString::npos) return;
  r.append_internal_result(0x572e7a0,
   "Vulnerable driver load enabled:::System Configuration:::The User modified his system to allow loading vulnerable drivers");
 });
}
// Seven synthetic original-instruction core fixtures confirm the predicate and
// exact internal result. Interpretation stopped at the timing epilogue's map
// access; this is not an all-path proof of runtime/recovery/provider internals.
// Global572e7a0 is merged with572e5e0 and transformed by HCZ3Ed in GoFq;
// the resulting572e5e0/e8/f0 slice feeds WARNINGS at mapsite1f05799.
// Review text only; registry access is a contract, never compiled/executed.
}
