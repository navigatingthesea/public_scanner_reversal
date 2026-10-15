#include "efi_bcd_and_bootloader.hpp"
#include <algorithm>
#include <array>
#include <cctype>

// Recovered behavior summary:
//   Input: BCD objects, firmware application records, and caller-provided suspicious path
//          substrings.
//   Gate: Excludes standard Windows bootloader paths, then applies lowercase substring matching to
//         candidate firmware applications.
//   Output: Builds readable BCD, bootloader, and firmware-application evidence records.
//   Failure: Object-open failure flags that object; the successful GRUB walk creates only the
//            recovered transient data and is not invented as persisted output.

namespace ocean::reconstructed::efi_bcd_bootloader {
namespace {
ByteString lower(ByteString value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  std::replace(value.begin(), value.end(), '\\', '/');
  return value;
}
bool ends_with(const ByteString& value, const ByteString& suffix) {
  return value.size() >= suffix.size() &&
         value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}
bool is_standard_windows_loader(const ByteString& path) {
  const auto p = lower(path);
  return ends_with(p, "/efi/microsoft/boot/bootmgfw.efi") ||
         ends_with(p, "/windows/system32/winload.efi") ||
         ends_with(p, "/windows/system32/winresume.efi") ||
         p == "bootmgfw.efi" || p == "winload.efi" || p == "winresume.efi";
}
}

// Original symbol: PEhVuBqkg8Zt.WFGMOK9r7C.
bool suspicious_firmware_application(const FirmwareApplication& app,
                                     const std::vector<ByteString>& suspicious_substrings) {
  if (is_standard_windows_loader(app.path)) return false;
  const auto combined = lower(app.device + ":" + app.path);
  // The recovered predicate first applies the standard-path exclusions above,
  // then performs substring membership against its initialized rule slice.
  return std::any_of(suspicious_substrings.begin(), suspicious_substrings.end(),
                     [&](const ByteString& rule) { return combined.find(lower(rule)) != ByteString::npos; });
}

// Original symbol: PEhVuBqkg8Zt.LEuAoZWf8.
std::shared_ptr<BcdObject> read_bcd_object(Provider& provider, std::uintptr_t store,
                                           const ByteString& identifier,
                                           const std::shared_ptr<BootloaderInfo>& bootloader) {
  auto result = std::make_shared<BcdObject>();
  result->identifier = provider.format_identifier(identifier);
  const auto opened = provider.open_object(store, identifier);
  if (!opened.error.empty() || opened.handle == 0) {
    result->flagged = true;
    result->flag_reason = opened.error;
    return result;
  }

  struct Close { Provider& p; std::uintptr_t h; ~Close() { p.close_object(h); } } close{provider, opened.handle};
  result->device = provider.read_element(opened.handle, Element::Device);
  result->path = provider.read_element(opened.handle, Element::Path);
  result->description = provider.read_element(opened.handle, Element::Description);
  result->locale = provider.read_element(opened.handle, Element::Locale);
  result->inherit = provider.read_element(opened.handle, Element::Inherit);
  result->default_object = provider.read_element(opened.handle, Element::DefaultObject);
  result->resumeobject = provider.read_element(opened.handle, Element::ResumeObject);
  result->displayorder = provider.read_element(opened.handle, Element::DisplayOrder);
  result->toolsdisplayorder = provider.read_element(opened.handle, Element::ToolsDisplayOrder);
  result->timeout = provider.read_element(opened.handle, Element::Timeout);
  result->recoverysequence = provider.read_element(opened.handle, Element::RecoverySequence);
  result->recoveryenabled = provider.read_element(opened.handle, Element::RecoveryEnabled);
  result->osdevice = provider.read_element(opened.handle, Element::OsDevice);
  result->systemroot = provider.read_element(opened.handle, Element::SystemRoot);
  result->nx = provider.read_element(opened.handle, Element::Nx);

  // The original walks firmware applications when GRUB was detected and formats
  // suspicious device/path/description triples. That temporary slice is not
  // assigned to BcdObject; the externally visible flag fields stay unchanged on
  // a successful object open. We preserve that observable behavior here.
  if (bootloader && bootloader->grub_detected) {
    std::vector<ByteString> transient;
    for (const auto& app : bootloader->firmware_applications) {
      if (suspicious_firmware_application(app, {}))
        transient.push_back("device=" + app.device + " path=" + app.path + " description=" + app.description);
    }
  }
  return result;
}

// Original symbol: PEhVuBqkg8Zt.BksYznAbx.
std::shared_ptr<BootloaderInfo> inspect_bootloader(Provider& provider, std::uintptr_t store,
                                                   const std::vector<ByteString>& suspicious_substrings) {
  auto out = std::make_shared<BootloaderInfo>();
  out->type = "Windows";                       // literal length 7 in the original
  out->firmware_type = provider.firmware_type();
  out->secure_boot = provider.registry_secure_boot_enabled();
  out->efi_partition = provider.locate_efi_partition();
  const auto enumerated = provider.enumerate_firmware_applications(store);
  if (enumerated.error.empty()) out->firmware_applications = enumerated.applications;

  for (const auto& app : out->firmware_applications) {
    if (!suspicious_firmware_application(app, suspicious_substrings)) continue;
    out->grub_detected = true;
    if (out->grub_path.empty()) out->grub_path = app.path;
    if (!app.description.empty()) out->grub_distros.push_back(app.description);
  }
  out->windows_bcd = provider.detect_grub(store, out->firmware_applications,
                                          out->efi_partition) == false;
  return out;
}

// Original symbol: PEhVuBqkg8Zt.elkDjLLG.
std::vector<FirmwareApplication> collect_bcd_paths(Provider& provider, std::uintptr_t store,
                                                   const std::shared_ptr<BcdObject>& bootmgr,
                                                   const std::shared_ptr<BcdObject>& current_os) {
  std::vector<FirmwareApplication> out;
  auto append = [&](const std::shared_ptr<BcdObject>& object) {
    if (!object) return;
    out.push_back({object->identifier, object->device, object->path, object->description});
  };
  append(bootmgr);
  append(current_os);
  const auto firmware = provider.enumerate_firmware_applications(store);
  if (firmware.error.empty()) out.insert(out.end(), firmware.applications.begin(), firmware.applications.end());
  return out;
}
}
