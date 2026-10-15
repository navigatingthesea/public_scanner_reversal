#include "efi_evidence_types.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <unordered_set>

// Recovered behavior summary:
//   Input: Primary and fallback EFI variable enumeration results.
//   Gate: Classifies recovered driver/sysprep/policy naming patterns, using fallback only under the
//         recovered conditions.
//   Output: Returns counts, per-variable flags, notes, and appends EFI-variable anomalies.
//   Failure: Enumeration limitations are retained in the note; name matches are heuristic
//            classifications.

namespace ocean::reconstructed::efi_variable_inventory {
using efi_evidence::EfiVariable;
using efi_evidence::EfiVariables;

static const std::unordered_set<ByteString> kKnownGlobalNames = {
  "KEK","PK","db","dbx","dbt","Lang","Timeout","ConOut","ConIn","ConErr","ErrOut","StdErr",
  "TimeOut","bootmgfw","OsIndications","OsIndicationsSupported","OsIndicationsSetup","SecureBoot",
  "SecureBootSetupMode","SecureBootPolicy","KEKDefault","PKDefault","dbDefault","dbxDefault",
  "BootOrder","BootCurrent","BootNext","BootPrevious","BootOptionSupport","BootBevDiscovered",
  "DriverOrder","DriverCurrent","DriverNext","SysPrepOrder","SysPrepCurrent","PlatformLang",
  "PlatformLangCodes","LangCodes","BootDelay","Boot0000","PlatformRecovery0000","SetupMode",
  "AuditMode","DeployedMode","VendorKeys","SignatureSupport","CertEnroll","TPMSecurityFailure",
  "HwErrRecSupport","DefaultBootBehavior","CurrentBoot","PrevBoot","BootChainLadder","TcgSecurity",
  "EFICapsuleFirmwareManifest","SysPrep0000","Driver0000","BootCounter","WakeupInfo","StdErrGuid"
};
static const std::unordered_set<ByteString> kRemovableMediaImages = {
  "bootx64.efi", "bootia32.efi", "bootaa64.efi"
};
static const std::unordered_set<ByteString> kPcrMeasuredVariables = {
  "PK","KEK","db","dbx","SecureBoot","SetupMode","AuditMode","DeployedMode","VendorKeys"
};

bool four_hex_suffix(const ByteString& value, const ByteString& prefix) {
  if (value.size() != prefix.size() + 4 || value.compare(0, prefix.size(), prefix) != 0) return false;
  return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(prefix.size()), value.end(),
                     [](unsigned char c) { return std::isxdigit(c) != 0; });
}

// Semantic reconstruction of wsP2om65QUV. Its two inputs are the primary
// firmware-environment enumeration and the secondary fallback enumeration.
std::shared_ptr<EfiVariables> classify(std::vector<EfiVariable> primary,
                                       std::vector<EfiVariable> fallback,
                                       bool os_is_live) {
  auto out = std::make_shared<EfiVariables>();
  out->values = std::move(primary);
  out->values.insert(out->values.end(), fallback.begin(), fallback.end());
  out->enumerated = static_cast<std::int64_t>(out->values.size());
  for (auto& variable : out->values) {
    const auto& name = variable.name;
    if (four_hex_suffix(name, "Driver")) ++out->driver_vars;
    if (four_hex_suffix(name, "SysPrep")) ++out->sysprep_vars;
    if (variable.guid == "{8be4df61-93ca-11d2-aa0d-00e098032b8c}" &&
        !kKnownGlobalNames.contains(name) &&
        !four_hex_suffix(name, "Boot") && !four_hex_suffix(name, "Driver") &&
        !four_hex_suffix(name, "SysPrep") && !four_hex_suffix(name, "PlatformRecovery")) {
      variable.flag = "UnknownGlobal:" + name;
      out->flags.push_back(variable.flag);
    }
    if (os_is_live && name == "OsIndications") {
      variable.flag = "PolicyTweak:" + name;
      out->flags.push_back(variable.flag);
    }
  }
  return out;
}

struct Reporter {
    virtual void console(const ByteString&) = 0;
    virtual void log(const ByteString&,const ByteString&,const ByteString&) = 0;
};

// Original symbol: PEhVuBqkg8Zt.QlrAXacq5.
void report(Reporter& reporter, EfiVariables& values, std::vector<ByteString>& anomalies) {
  if (values.driver_vars + values.sysprep_vars > 0) {
    reporter.console(
        "EFI NVRAM Rogue Boot Entry [TYPE V6]:::Boot instance:::"
        "Driver####/SysPrep#### bootmgr entries are present — no legitimate Windows install ships these");
    reporter.log("EFINames", "Rogue Driver/SysPrep variables",
                 "driver_vars=" + std::to_string(values.driver_vars) + " sysprep_vars=" + std::to_string(values.sysprep_vars));
  }
  std::int64_t unknown = 0, policy = 0;
  for (const auto& flag : values.flags) {
    if (flag.starts_with("UnknownGlobal:")) ++unknown;
    if (flag.starts_with("PolicyTweak:")) ++policy;
  }
  if (unknown)
    anomalies.push_back("EFI NVRAM Anomaly:::Boot instance:::" + std::to_string(unknown) +
                        " unknown variable(s) in EFI_GLOBAL_VARIABLE namespace");
  if (policy)
    anomalies.push_back(
        "EFI NVRAM Anomaly:::Boot instance:::OsIndications written while the OS was live — "
        "a boot-policy toggle was staged for next reboot");
  if (!values.flags.empty()) {
    ByteString joined;
    for (const auto& flag : values.flags) { if (!joined.empty()) joined += ", "; joined += flag; }
    reporter.log("EFINames", "EFI variable flags", joined);
  }
}
}
