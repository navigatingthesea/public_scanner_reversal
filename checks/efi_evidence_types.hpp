#pragma once
#include "../session/session_types.hpp"
#include <memory>
#include <optional>
#include <unordered_map>
// Recovered behavior summary:
//   Input: Recovered semantic fields and captured Go offsets/JSON tags for EFI boot evidence.
//   Gate: No detection predicate runs in this metadata file.
//   Output: Provides the shared typed records used by EFI collectors and classifiers.
//   Failure: C++ layouts are documentation models and are not claimed ABI-compatible with Go.

namespace ocean::reconstructed::efi_evidence {
//Readable semantic fields; C++ layout is not asserted binary-compatible with Go.
//Exact JSON tags/Go offsets below are captured metadata, including omitempty.
struct BootEvidence;
struct SystemFirmwareInfo;
struct BcdObject;
struct BootloaderInfo;
struct FirmwareApplication;
struct SecureBootState;
struct MeasuredBootState;
struct TpmDeviceInfo;
struct Pcr7Measurements;
struct MeasuredVariable;
struct Pcr0Measurements;
struct BootImage;
struct BootImageFingerprint;
struct EfiVariables;
struct EfiVariable;

struct SystemFirmwareInfo { //Go 0x375d040, size80
 ByteString bios_vendor{}; //Go+0 json:"bios_vendor"
 ByteString bios_version{}; //Go+16 json:"bios_version"
 ByteString board_manufacturer{}; //Go+32 json:"board_manufacturer"
 ByteString board_product{}; //Go+48 json:"board_product"
 ByteString board_version{}; //Go+64 json:"board_version"
};

struct SecureBootState { //Go 0x3794c60, size112
 bool registry_enabled{}; //Go+0 json:"registry_enabled"
 bool firmware_enabled{}; //Go+1 json:"firmware_enabled"
 bool consistent{}; //Go+2 json:"consistent"
 ByteString policy_publisher{}; //Go+8 json:"policy_publisher,omitempty"
 bool fake_policy_guid{}; //Go+24 json:"fake_policy_guid"
 std::optional<bool> setup_mode{}; //Go+32 json:"setup_mode,omitempty"
 std::optional<bool> audit_mode{}; //Go+40 json:"audit_mode,omitempty"
 std::optional<bool> deployed_mode{}; //Go+48 json:"deployed_mode,omitempty"
 std::optional<bool> vendor_keys{}; //Go+56 json:"vendor_keys,omitempty"
 std::optional<std::uint32_t> available_updates{}; //Go+64 json:"available_updates,omitempty"
 std::optional<std::uint32_t> available_updates_policy{}; //Go+72 json:"available_updates_policy,omitempty"
 ByteString uefica2023_status{}; //Go+80 json:"uefica2023_status,omitempty"
 std::optional<std::uint32_t> uefica2023_error{}; //Go+96 json:"uefica2023_error,omitempty"
 std::optional<std::uint32_t> windows_uefica2023_capable{}; //Go+104 json:"windows_uefica2023_capable,omitempty"
};

struct TpmDeviceInfo { //Go 0x3784740, size120
 bool present{}; //Go+0 json:"present"
 ByteString version{}; //Go+8 json:"version,omitempty"
 std::uint32_t tbs_tpm_version_raw{}; //Go+24 json:"tbs_tpm_version_raw,omitempty"
 std::uint32_t tbs_struct_version{}; //Go+28 json:"tbs_struct_version,omitempty"
 ByteString spec_version{}; //Go+32 json:"spec_version,omitempty"
 ByteString manufacturer_id{}; //Go+48 json:"manufacturer_id,omitempty"
 std::optional<std::uint32_t> manufacturer_id_raw{}; //Go+64 json:"manufacturer_id_raw,omitempty"
 ByteString manufacturer_version{}; //Go+72 json:"manufacturer_version,omitempty"
 ByteString physical_presence_version{}; //Go+88 json:"physical_presence_version,omitempty"
 ByteString tbs_read_error{}; //Go+104 json:"tbs_read_error,omitempty"
};

struct MeasuredBootState { //Go 0x3790fe0, size272
 bool available{}; //Go+0 json:"available"
 TpmDeviceInfo device{}; //Go+8 json:"device,omitempty"
 std::int64_t gpt_count_pcr5{}; //Go+128 json:"gpt_count_pcr5"
 std::int64_t efi_images_loaded{}; //Go+136 json:"efi_images_loaded"
 bool is_normal_boot{}; //Go+144 json:"is_normal_boot"
 ByteString log_format{}; //Go+152 json:"log_format,omitempty"
 std::int64_t total_events_parsed{}; //Go+168 json:"total_events_parsed,omitempty"
 std::vector<ByteString> anomaly_details{}; //Go+176 json:"anomaly_details,omitempty"
 std::shared_ptr<Pcr7Measurements> pcr7{}; //Go+200 json:"pcr7,omitempty"
 std::shared_ptr<Pcr0Measurements> pcr0{}; //Go+208 json:"pcr0,omitempty"
 bool boot_chain_from_wbcl{}; //Go+216 json:"boot_chain_from_wbcl,omitempty"
 std::vector<BootImage> boot_chain{}; //Go+224 json:"boot_chain"
 std::vector<BootImageFingerprint> fingerprint{}; //Go+248 json:"fingerprint"
};

struct BootEvidence { //Go 0x378d080, size576
 SystemFirmwareInfo system{}; //Go+0 json:"system"
 bool bcd_success{}; //Go+80 json:"bcd_success"
 ByteString bcd_error{}; //Go+88 json:"bcd_error,omitempty"
 bool native_os_exists{}; //Go+104 json:"native_os_exists"
 std::shared_ptr<BcdObject> bootmgr{}; //Go+112 json:"bootmgr,omitempty"
 std::shared_ptr<BcdObject> current_os{}; //Go+120 json:"current_os,omitempty"
 std::shared_ptr<BootloaderInfo> bootloader{}; //Go+128 json:"bootloader,omitempty"
 SecureBootState secure_boot{}; //Go+136 json:"secure_boot"
 MeasuredBootState tpm{}; //Go+248 json:"tpm"
 std::vector<ByteString> anomalies{}; //Go+520 json:"anomalies"
 std::vector<FirmwareApplication> bcd_paths{}; //Go+544 json:"bcd_paths,omitempty"
 std::shared_ptr<EfiVariables> efi_names{}; //Go+568 json:"efi_names,omitempty"
};

struct BcdObject { //Go 0x379c160, size280
 ByteString identifier{}; //Go+0 json:"identifier"
 ByteString device{}; //Go+16 json:"device,omitempty"
 ByteString path{}; //Go+32 json:"path,omitempty"
 ByteString description{}; //Go+48 json:"description,omitempty"
 ByteString locale{}; //Go+64 json:"locale,omitempty"
 ByteString inherit{}; //Go+80 json:"inherit,omitempty"
 ByteString default_object{}; //Go+96 json:"default,omitempty"
 ByteString resumeobject{}; //Go+112 json:"resumeobject,omitempty"
 ByteString displayorder{}; //Go+128 json:"displayorder,omitempty"
 ByteString toolsdisplayorder{}; //Go+144 json:"toolsdisplayorder,omitempty"
 ByteString timeout{}; //Go+160 json:"timeout,omitempty"
 ByteString recoverysequence{}; //Go+176 json:"recoverysequence,omitempty"
 ByteString recoveryenabled{}; //Go+192 json:"recoveryenabled,omitempty"
 ByteString osdevice{}; //Go+208 json:"osdevice,omitempty"
 ByteString systemroot{}; //Go+224 json:"systemroot,omitempty"
 ByteString nx{}; //Go+240 json:"nx,omitempty"
 bool flagged{}; //Go+256 json:"flagged"
 ByteString flag_reason{}; //Go+264 json:"flagReason,omitempty"
};

struct BootloaderInfo { //Go 0x37845e0, size152
 ByteString type{}; //Go+0 json:"type"
 ByteString primary{}; //Go+16 json:"primary"
 bool grub_detected{}; //Go+32 json:"grub_detected"
 ByteString grub_path{}; //Go+40 json:"grub_path,omitempty"
 std::vector<ByteString> grub_distros{}; //Go+56 json:"grub_distros,omitempty"
 std::vector<FirmwareApplication> firmware_applications{}; //Go+80 json:"firmware_applications,omitempty"
 bool windows_bcd{}; //Go+104 json:"windows_bcd"
 ByteString efi_partition{}; //Go+112 json:"efi_partition,omitempty"
 bool secure_boot{}; //Go+128 json:"secure_boot"
 ByteString firmware_type{}; //Go+136 json:"firmware_type"
};

struct FirmwareApplication { //Go 0x374e700, size64
 ByteString identifier{}; //Go+0 json:"identifier"
 ByteString device{}; //Go+16 json:"device,omitempty"
 ByteString path{}; //Go+32 json:"path,omitempty"
 ByteString description{}; //Go+48 json:"description,omitempty"
};

struct Pcr7Measurements { //Go 0x377a680, size80
 std::int64_t total_events{}; //Go+0 json:"total_events"
 std::vector<MeasuredVariable> variables{}; //Go+8 json:"variables,omitempty"
 std::optional<bool> secure_boot_enabled{}; //Go+32 json:"secure_boot_enabled,omitempty"
 std::optional<bool> setup_mode{}; //Go+40 json:"setup_mode,omitempty"
 std::optional<bool> audit_mode{}; //Go+48 json:"audit_mode,omitempty"
 std::optional<bool> deployed_mode{}; //Go+56 json:"deployed_mode,omitempty"
 std::optional<bool> vendor_keys{}; //Go+64 json:"vendor_keys,omitempty"
 bool signature_databases_present{}; //Go+72 json:"signature_databases_present"
};

struct MeasuredVariable { //Go 0x368c2c0, size32
 ByteString name{}; //Go+0 json:"name"
 std::int64_t size{}; //Go+16 json:"size"
 std::optional<bool> enabled{}; //Go+24 json:"enabled,omitempty"
};

struct Pcr0Measurements { //Go 0x3768a80, size88
 std::int64_t event_count{}; //Go+0 json:"event_count"
 ByteString sha256{}; //Go+8 json:"sha256,omitempty"
 ByteString sha1{}; //Go+24 json:"sha1,omitempty"
 std::vector<ByteString> digest_algs{}; //Go+40 json:"digest_algs,omitempty"
 std::optional<bool> changed_since_last_boot{}; //Go+64 json:"changed_since_last_boot,omitempty"
 ByteString previous_sha256{}; //Go+72 json:"previous_sha256,omitempty"
};

struct BootImage { //Go 0x37986e0, size160
 ByteString file_name{}; //Go+0 json:"file_name"
 std::uint64_t memory_address{}; //Go+16 json:"memory_address"
 ByteString disk_guid{}; //Go+24 json:"disk_guid"
 ByteString partition_guid{}; //Go+40 json:"partition_guid,omitempty"
 ByteString device_path_hex{}; //Go+56 json:"device_path_hex,omitempty"
 std::unordered_map<ByteString,ByteString> hashes{}; //Go+72 json:"hashes,omitempty"
 ByteString sha256{}; //Go+80 json:"sha256,omitempty"
 std::uint64_t size_kb{}; //Go+96 json:"size_kb,omitempty"
 ByteString drive_type{}; //Go+104 json:"drive_type,omitempty"
 ByteString tpm_basename{}; //Go+120 json:"tpm_basename,omitempty"
 ByteString wbcl_path{}; //Go+136 json:"wbcl_path,omitempty"
 bool wbcl_path_trustworthy{}; //Go+152 json:"wbcl_path_trustworthy,omitempty"
 bool tpm_basename_usable_for_bcd_compare{}; //Go+153 json:"tpm_basename_usable_for_bcd_compare,omitempty"
 bool skip_bcd_compare{}; //Go+154 json:"skip_bcd_compare,omitempty"
 bool bcd_match{}; //Go+155 json:"bcd_match,omitempty"
 bool load_address_mismatch{}; //Go+156 json:"load_address_mismatch,omitempty"
};

struct BootImageFingerprint { //Go 0x374e640, size48
 std::int64_t index{}; //Go+0 json:"index"
 ByteString file_name{}; //Go+8 json:"file_name"
 ByteString partition_guid_prefix{}; //Go+24 json:"partition_guid_prefix"
 std::uint64_t memory_address{}; //Go+40 json:"memory_address"
};

struct EfiVariables { //Go 0x3768b80, size88
 std::int64_t enumerated{}; //Go+0 json:"enumerated"
 std::int64_t driver_vars{}; //Go+8 json:"driver_vars"
 std::int64_t sysprep_vars{}; //Go+16 json:"sysprep_vars"
 std::vector<ByteString> flags{}; //Go+24 json:"flags,omitempty"
 std::vector<EfiVariable> values{}; //Go+48 json:"values,omitempty"
 ByteString note{}; //Go+72 json:"note,omitempty"
};

struct EfiVariable { //Go 0x375cf60, size80
 ByteString name{}; //Go+0 json:"name"
 ByteString guid{}; //Go+16 json:"guid"
 ByteString attributes{}; //Go+32 json:"attributes,omitempty"
 ByteString value_hex{}; //Go+48 json:"value_hex,omitempty"
 ByteString flag{}; //Go+64 json:"flag,omitempty"
};

struct WbclImageRecord { //internal Go377a560 size112, no JSON tags
 std::int64_t index;ByteString path,sha256;std::uint64_t size_kb,memory_address;
 std::vector<ByteString> nodes;ByteString partition_guid,drive_type;
};
//Metadata and parsed-input definitions; root EFI classification is implemented in efi_boot_root.cpp.
//Guest-only review source; never compiled or run.
}
