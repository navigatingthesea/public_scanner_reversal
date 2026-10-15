#pragma once
#include "efi_evidence_types.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

// Recovered behavior summary:
//   Input: Typed provider boundary for BCD object opens, element reads, firmware application
//          enumeration, and identifier formatting.
//   Gate: Element identifiers and returned fields mirror the recovered calls.
//   Output: Declares the BCD and bootloader reconstruction API.
//   Failure: All Windows BCD access remains behind Provider; no success is assumed.

namespace ocean::reconstructed::efi_bcd_bootloader {
using efi_evidence::BcdObject;
using efi_evidence::BootloaderInfo;
using efi_evidence::FirmwareApplication;

// Element identifiers passed to BcdGetElementData by the recovered program.
enum class Element : std::uint32_t {
  Device = 0x11000001,
  Path = 0x12000002,
  Description = 0x12000004,
  Locale = 0x12000005,
  Inherit = 0x14000006,
  DefaultObject = 0x23000003,
  ResumeObject = 0x23000006,
  DisplayOrder = 0x24000001,
  ToolsDisplayOrder = 0x24000010,
  Timeout = 0x25000004,
  RecoverySequence = 0x14000008,
  RecoveryEnabled = 0x16000009,
  OsDevice = 0x21000001,
  SystemRoot = 0x22000002,
  Nx = 0x25000020,
};

struct OpenResult {
    std::uintptr_t handle{};
    ByteString error{};
    std::int64_t error_code{};
};
struct ApplicationResult {
    std::vector<FirmwareApplication> applications{};
    ByteString error{};
};

struct Provider {
  virtual ByteString firmware_type() = 0;                 // GetFirmwareType, filesystem fallback
  virtual bool registry_secure_boot_enabled() = 0;       // HKLM SecureBoot State DWORD == 1
  virtual ByteString locate_efi_partition() = 0;         // scans A: through Z:
  virtual ApplicationResult enumerate_firmware_applications(std::uintptr_t store) = 0;
  virtual bool detect_grub(std::uintptr_t store,
                           const std::vector<FirmwareApplication>& applications,
                           const ByteString& efi_partition) = 0;
  virtual OpenResult open_object(std::uintptr_t store, const ByteString& identifier) = 0;
  virtual void close_object(std::uintptr_t handle) = 0;
  virtual ByteString read_element(std::uintptr_t object, Element element) = 0;
  virtual ByteString format_identifier(const ByteString& identifier) = 0;
  virtual ~Provider() = default;
};

bool suspicious_firmware_application(const FirmwareApplication& app,
                                     const std::vector<ByteString>& suspicious_substrings);
std::shared_ptr<BcdObject> read_bcd_object(Provider& provider, std::uintptr_t store,
                                           const ByteString& identifier,
                                           const std::shared_ptr<BootloaderInfo>& bootloader);
std::shared_ptr<BootloaderInfo> inspect_bootloader(Provider& provider, std::uintptr_t store,
                                                   const std::vector<ByteString>& suspicious_substrings);
std::vector<FirmwareApplication> collect_bcd_paths(Provider& provider, std::uintptr_t store,
                                                   const std::shared_ptr<BcdObject>& bootmgr,
                                                   const std::shared_ptr<BcdObject>& current_os);
}
