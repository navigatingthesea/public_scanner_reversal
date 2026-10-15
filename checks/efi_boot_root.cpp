#include "efi_boot_root.hpp"
#include <chrono>
#include <thread>

// Recovered behavior summary:
//   Input: TPM, BIOS, Secure Boot, EFI-variable, BCD, bootloader, and WBCL providers.
//   Gate: Runs collectors in recovered order, retries only the captured BCD open errors, and
//         classifies the assembled evidence.
//   Output: Returns serialized BootEvidence and emits the recovered firmware/boot anomaly rows.
//   Failure: BCD library/load or store-open failure takes the corresponding partial-finalization
//            path.

namespace ocean::reconstructed::efi_boot_correlation {
struct Reporter {
    virtual void console(const ByteString&)=0;
    virtual void log(const ByteString&,const ByteString&,const ByteString&)=0;
};
void correlate(efi_evidence::BootEvidence&, const std::vector<efi_evidence::WbclImageRecord>&,
               const std::vector<efi_evidence::WbclImageRecord>&, Reporter&);
void classify_windows_bootloader_presence(const efi_evidence::BootEvidence&, Reporter&);
std::vector<ByteString> gpt_count_anomalies(const efi_evidence::MeasuredBootState&);
}

namespace ocean::reconstructed::efi_boot_root {
namespace {
constexpr std::int64_t kSharingViolation = -0x3fffffbd; // NTSTATUS 0xC0000043
constexpr std::int64_t kAccessDenied = -0x3fffffde;     // NTSTATUS 0xC0000022
constexpr std::int64_t kPrivilegeNotHeld = -0x3fffff9f;// NTSTATUS 0xC0000061

StoreResult open_store_with_retry(Provider& provider) { //e3a8EQP
  StoreResult result;
  for (int attempt = 0; attempt != 3; ++attempt) {
    result = provider.open_bcd_store();
    if (!result.error || result.error.code != kSharingViolation) return result;
    if (attempt != 2) std::this_thread::sleep_for(std::chrono::milliseconds(150));
  }
  return result;
}

void report_generic_firmware_applications(Reporter& reporter,
                                           const std::vector<FirmwareApplication>& applications) { //P6T0 + rV5
  for (const auto& app : applications) {
    if (app.description != "UEFI: Generic") continue;
    reporter.console("Generic EFI Modification [TYPE V1]:::Boot instance");
    reporter.log("EFI Boot Check", "EFI Bootkit / External HWID Spoofer Vector",
                 "description=\"" + app.description + "\" identifier=" + app.identifier +
                 " device=" + app.device + " path=" + app.path);
  }
}

struct CorrelationReporterAdapter final : efi_boot_correlation::Reporter {
  Reporter& out; explicit CorrelationReporterAdapter(Reporter& value):out(value){}
  void console(const ByteString& s) override { out.console(s); }
  void log(const ByteString& a,const ByteString& b,const ByteString& c) override { out.log(a,b,c); }
};
}

// Original root: PEhVuBqkg8Zt.GfPkPdJEPPRE. This is its recovered execution
// order, including the two early partial-finalization paths.
ByteString execute(Provider& provider, Reporter& reporter,
                   const std::vector<ByteString>& suspicious_firmware_substrings) {
  BootEvidence evidence;
  const auto wbcl = provider.collect_wbcl_images();        // ApllxOqd
  evidence.tpm = provider.collect_measured_boot();         // uSa9q8FJKxc
  evidence.system = provider.collect_bios();               // ptrVxWaE
  evidence.secure_boot = provider.collect_secure_boot();   // y_LztuEZq
  provider.classify_pcr7(evidence);                        // esWdXjxfdghK

  for (const auto& privilege : {"SeSystemEnvironmentPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"})
    provider.enable_privilege(privilege);                  // HAiKJacgJP; errors are logged but nonfatal
  evidence.efi_names = provider.enumerate_efi_variables(); // QlrAXacq5

  if (const auto error = provider.initialize_bcd_api()) {  // ViwHWaKr4Xv
    evidence.bcd_success = false;
    evidence.bcd_error = "Cannot load bcd.dll: " + error.text;
    CorrelationReporterAdapter adapter(reporter);
    efi_boot_correlation::correlate(evidence, wbcl, {}, adapter);
    efi_boot_correlation::classify_windows_bootloader_presence(evidence, adapter);
    return provider.serialize(evidence);                   // mb8KZTx7E partial finalizer
  }

  const auto opened = open_store_with_retry(provider);     // e3a8EQP
  if (opened.error || opened.handle == 0) {
    evidence.bcd_success = false;
    evidence.bcd_error = "Cannot open BCD store: " + opened.error.text;
    if (opened.error.code != kAccessDenied && opened.error.code != kPrivilegeNotHeld)
      reporter.log("EFI Boot Check", "BCD store open failed (non-access-denied)", evidence.bcd_error);
    CorrelationReporterAdapter adapter(reporter);
    efi_boot_correlation::correlate(evidence, wbcl, {}, adapter);
    efi_boot_correlation::classify_windows_bootloader_presence(evidence, adapter);
    return provider.serialize(evidence);
  }
  struct CloseStore { Provider& p; std::uintptr_t h; ~CloseStore(){p.close_bcd_store(h);} } close{provider,opened.handle};
  evidence.bcd_success = true;
  evidence.bootloader = efi_bcd_bootloader::inspect_bootloader(provider, opened.handle,
                                                                suspicious_firmware_substrings);
  report_generic_firmware_applications(reporter, evidence.bootloader->firmware_applications);
  evidence.bootmgr = efi_bcd_bootloader::read_bcd_object(provider, opened.handle, "{bootmgr}", evidence.bootloader);
  evidence.current_os = efi_bcd_bootloader::read_bcd_object(provider, opened.handle, "{current}", evidence.bootloader);
  evidence.bcd_paths = efi_bcd_bootloader::collect_bcd_paths(provider, opened.handle,
                                                              evidence.bootmgr, evidence.current_os);

  evidence.native_os_exists = evidence.bootmgr && !evidence.bootmgr->displayorder.empty() &&
                              evidence.current_os && !evidence.current_os->systemroot.empty() &&
                              !evidence.current_os->path.empty();
  if (evidence.native_os_exists) {
    reporter.log("Native OS Check", "Native Operating System detected in BCD.", "");
  } else {
    ByteString reason;
    if (!evidence.bootmgr || evidence.bootmgr->displayorder.empty())
      reason += "Boot Manager DisplayOrder is empty or missing.";
    if (!evidence.current_os || evidence.current_os->systemroot.empty() || evidence.current_os->path.empty())
      reason += " Current OS object is invalid or missing SystemRoot/Path.";
    reporter.console("Generic EFI Modification [TYPE V6]:::In instance:::");
    reporter.log("EFI Boot Check", "Native OS missing or invalid in BCD",
                 reason + " bootmgr: " + (evidence.bootmgr ? evidence.bootmgr->identifier : "") +
                 " current_os: " + (evidence.current_os ? evidence.current_os->identifier : ""));
  }

  std::vector<WbclImageRecord> candidates;
  std::int64_t ordinal = 1;
  for (const auto& app : evidence.bcd_paths)
    candidates.push_back({ordinal++, app.path, "", 0, 0, {}, "", app.description}); //x2WtcI projection
  CorrelationReporterAdapter adapter(reporter);
  efi_boot_correlation::correlate(evidence, wbcl, candidates, adapter); //hTxeMoFB
  efi_boot_correlation::classify_windows_bootloader_presence(evidence, adapter); //eESkyNiOov

  if (evidence.bootmgr && evidence.bootmgr->flagged)
    evidence.anomalies.push_back(evidence.bootmgr->flag_reason);
  if (evidence.current_os && evidence.current_os->flagged)
    evidence.anomalies.push_back(evidence.current_os->flag_reason);
  const auto measured = efi_boot_correlation::gpt_count_anomalies(evidence.tpm);
  evidence.anomalies.insert(evidence.anomalies.end(), measured.begin(), measured.end());
  if (!evidence.tpm.available) reporter.log("EFI Boot Check", "No hay tpm log", "");
  reporter.log("EFI Boot Check", "BCD integrity verified", "");
  return provider.serialize(evidence);                     // eqWZErvpAhIb
}
}
