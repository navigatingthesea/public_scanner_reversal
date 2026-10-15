#include "efi_evidence_types.hpp"
// Recovered behavior summary:
//   Input: Already-collected PCR7 measurements and SecureBootState fields.
//   Gate: Applies the recovered consistency, mode, variable-presence, and signature-database
//         comparisons.
//   Output: Emits only the findings associated with matching PCR7/Secure Boot states.
//   Failure: Missing evidence follows explicit no-data branches; this file performs no TPM,
//            firmware, or registry reads.

namespace ocean::reconstructed::efi_pcr7_classifier {
using namespace efi_evidence;
struct Contracts {
 virtual void console(const ByteString&)=0;
 virtual void append_debug(const std::vector<ByteString>&)=0;
 virtual void log(const std::vector<ByteString>&)=0;
};
static ByteString shown(const std::optional<bool>& value){ //eHJoPaa
 return !value?"unmeasured":(*value?"true":"false");
}
static ByteString yesno(bool value){return value?"true":"false";}
void classify(Contracts& out,const BootEvidence* evidence){ //esWdXjxfdghK@12a5140
 if(!evidence || !evidence->tpm.pcr7)return;
 const auto& pcr=*evidence->tpm.pcr7;const auto& secure=evidence->secure_boot;
 if(pcr.total_events>0 && pcr.variables.empty())
  out.log({"PCR7","No standard Secure Boot variables measured","total_events="+std::to_string(pcr.total_events)});
 if(pcr.secure_boot_enabled && !*pcr.secure_boot_enabled && secure.registry_enabled){
  out.console("Secure Boot Mismatch:::Boot instance:::");
  out.append_debug({"TPMEfi","PCR7 SecureBoot=0 vs registry enabled",
   "pcr7_secure_boot=false registry_enabled="+yesno(secure.registry_enabled)+
   " setup_mode="+shown(pcr.setup)+" audit_mode="+shown(pcr.audit)});
 }
 if(pcr.setup && *pcr.setup && pcr.vendor_keys && *pcr.vendor_keys){
  out.console("Secure Boot Mismatch:::Boot instance:::");
  out.append_debug({"TPMEfi","PCR7 SetupMode with VendorKeys",
   "setup_mode=true vendor_keys=true signature_databases_present="+yesno(pcr.signature_databases_present)});
 }
 if(pcr.audit && *pcr.audit){
  out.console("Secure Boot Mismatch:::Boot instance:::");
  out.append_debug({"TPMEfi","PCR7 AuditMode active",
   "audit_mode=true deployed_mode="+shown(pcr.deployed)});
 }
 if(pcr.secure_boot_enabled && !*pcr.secure_boot_enabled)
  out.log({"PCR7","Measured boot without Secure Boot",
   "registry_enabled="+yesno(secure.registry_enabled)+
   " firmware_enabled="+yesno(secure.firmware_enabled)+
   " consistent="+yesno(secure.consistent)});
}
//19 original control fixtures. These branches inspect already-collected PCR7
//and SecureBootState values; they do not read TPM/registry/firmware themselves.
//The two log-only observations above do not append a detection. No source run.
}
