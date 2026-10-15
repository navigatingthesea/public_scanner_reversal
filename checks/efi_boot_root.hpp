#pragma once
#include "efi_bcd_and_bootloader.hpp"
#include "efi_evidence_types.hpp"
#include <memory>
#include <vector>

// Recovered behavior summary:
//   Input: Provider and reporter interfaces for the EFI/BCD root orchestration.
//   Gate: Provider results carry explicit handles, errors, and collected evidence.
//   Output: Declares the single execute entry point returning serialized evidence.
//   Failure: Native calls, closing, serialization, and reporting remain explicit provider
//            boundaries.

namespace ocean::reconstructed::efi_boot_root {
using namespace efi_evidence;
struct Error { ByteString text{}; std::int64_t code{}; explicit operator bool() const { return !text.empty() || code != 0; } };
struct StoreResult {
    std::uintptr_t handle{};
    Error error{};
};
struct Reporter {
    virtual void console(const ByteString&)=0;
    virtual void log(const ByteString&,const ByteString&,const ByteString&)=0;
};
struct Provider : efi_bcd_bootloader::Provider {
  virtual SystemFirmwareInfo collect_bios()=0;
  virtual SecureBootState collect_secure_boot()=0;
  virtual MeasuredBootState collect_measured_boot()=0;
  virtual std::vector<WbclImageRecord> collect_wbcl_images()=0;
  virtual std::shared_ptr<EfiVariables> enumerate_efi_variables()=0;
  virtual void classify_pcr7(BootEvidence&)=0;
  virtual Error enable_privilege(const ByteString&)=0;
  virtual Error initialize_bcd_api()=0;
  virtual StoreResult open_bcd_store()=0;
  virtual void close_bcd_store(std::uintptr_t)=0;
  virtual bool elevated()=0;
  virtual ByteString serialize(const BootEvidence&)=0;
};
ByteString execute(Provider&, Reporter&, const std::vector<ByteString>& suspicious_firmware_substrings);
}
