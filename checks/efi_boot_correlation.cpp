#include "efi_evidence_types.hpp"
#include <algorithm>
#include <array>
#include <cctype>

// Recovered behavior summary:
//   Input: Measured boot images, WBCL fallback paths, BCD paths, basenames, addresses, and GPT
//          counts.
//   Gate: Correlates by usable basename and ordinal, applies removable-loader exceptions, then
//         records BCD/path/address mismatches.
//   Output: Mutates BootEvidence correlation fields and emits bootloader/GPT anomaly reports.
//   Failure: Path trust is syntactic and does not prove file existence; absent or ambiguous
//            evidence remains explicit.

namespace ocean::reconstructed::efi_boot_correlation {
using namespace efi_evidence;

struct Reporter {
  virtual void console(const ByteString&) = 0;
  virtual void log(const ByteString&, const ByteString&, const ByteString&) = 0;
};

ByteString lower_path(ByteString value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  std::replace(value.begin(), value.end(), '\\', '/');
  return value;
}
ByteString basename(ByteString value) {
  value = lower_path(std::move(value));
  const auto split = value.find_last_of('/');
  return split == ByteString::npos ? value : value.substr(split + 1);
}

// Original cbwRJunVY: path syntax is accepted, not file existence.
bool trustworthy_path(const ByteString& raw) {
  const auto p = lower_path(raw);
  return !p.empty() && p.size() <= 1024 &&
         ((p.size() >= 4 && p.ends_with(".efi")) || (p.size() > 5 && p.find('/') != ByteString::npos));
}

// Original eRh2aYlofQM8.
bool usable_basename(const ByteString& value) {
  if (value.empty() || value == "." || value == ".." || value.size() >= 513) return false;
  bool alphanumeric = false;
  for (unsigned char c : value) {
    if (c < 0x20 || c == 0x7f) return false;
    if (std::isalnum(c)) alphanumeric = true;
  }
  return alphanumeric && value.find("\xEF\xBF\xBD") == ByteString::npos;
}

// Original xoxWRq. This avoids BCD comparison for standard removable-media
// loaders: any path under \EFI\Boot\, or a missing path whose basename is one
// of the four architecture defaults decoded from the binary.
bool skip_bcd_compare(const ByteString& wbcl_path, const ByteString& tpm_basename) {
  ByteString windows = wbcl_path;
  std::transform(windows.begin(), windows.end(), windows.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (windows.find("\\efi\\boot\\") != ByteString::npos) return true;
  if (!wbcl_path.empty()) return false;
  const auto name = basename(tpm_basename);
  static constexpr std::array<const char*, 4> allowed = {
    "bootx64.efi", "bootia32.efi", "bootaa64.efi", "bootriscv64.efi"
  };
  return std::any_of(allowed.begin(), allowed.end(), [&](const char* item) { return name == item; });
}

bool path_matches(const std::vector<WbclImageRecord>& candidates,
                  const ByteString& path, const ByteString& name) {
  const auto p = lower_path(path), n = lower_path(name);
  for (const auto& candidate : candidates) {
    const auto c = lower_path(candidate.path);
    for (const auto& target : {p, n}) {
      if (target.empty()) continue;
      if (c == target || c.ends_with("/" + target) || basename(c) == basename(target)) return true;
    }
  }
  return false;
}

// Original iywaCagr: prefer same basename and the one-based event ordinal;
// otherwise use the first basename match, then the one-based ordinal fallback.
const WbclImageRecord* match_candidate(std::size_t zero_based_index, const ByteString& name,
                                       const std::vector<WbclImageRecord>& candidates) {
  const auto wanted = basename(name);
  const WbclImageRecord* first = nullptr;
  if (usable_basename(wanted)) {
    for (const auto& candidate : candidates) {
      if (basename(candidate.path) != wanted) continue;
      if (!first) first = &candidate;
      if (candidate.index == static_cast<std::int64_t>(zero_based_index + 1)) return &candidate;
    }
    if (first) return first;
  }
  for (const auto& candidate : candidates)
    if (candidate.index == static_cast<std::int64_t>(zero_based_index + 1)) return &candidate;
  return nullptr;
}

// Original hTxeMoFB.
void correlate(BootEvidence& evidence, const std::vector<WbclImageRecord>& wbcl_fallback,
               const std::vector<WbclImageRecord>& bcd_candidates, Reporter& reporter) {
  auto& measured = evidence.tpm;
  if (measured.efi_images_loaded == 0) {
    measured.boot_chain.clear();
    measured.fingerprint.clear();
    for (const auto& input : wbcl_fallback) {
      BootImage image;
      image.file_name = input.path; image.sha256 = input.sha256;
      image.size_kb = input.size_kb; image.memory_address = input.memory_address;
      image.partition_guid = input.partition_guid; image.drive_type = input.drive_type;
      measured.boot_chain.push_back(std::move(image));
      measured.fingerprint.push_back({input.index, input.path,
                                      input.partition_guid.substr(0, std::min<std::size_t>(8, input.partition_guid.size())),
                                      input.memory_address});
    }
    measured.efi_images_loaded = static_cast<std::int64_t>(measured.boot_chain.size());
    measured.boot_chain_from_wbcl = true;
    if (measured.boot_chain.empty())
      reporter.log("WBCL integrity", "WBCL fallback produced zero entries",
                   "TPM efi_images_loaded=0 and the WBCL fallback chain is also empty; boot chain verification skipped for this session.");
    return;
  }

  bool any_bcd_mismatch = false, any_address_mismatch = false;
  for (std::size_t index = 0; index < measured.boot_chain.size(); ++index) {
    auto& image = measured.boot_chain[index];
    image.tpm_basename = basename(image.file_name);
    const auto* candidate = match_candidate(index, image.tpm_basename, bcd_candidates);
    if (candidate) {
      image.wbcl_path = candidate->path;
      image.file_name = candidate->path;
      if (!candidate->sha256.empty()) image.sha256 = candidate->sha256;
      image.size_kb = candidate->size_kb;
      image.partition_guid = candidate->partition_guid;
      image.drive_type = candidate->drive_type;
      if (image.memory_address && candidate->memory_address && image.memory_address != candidate->memory_address) {
        image.load_address_mismatch = true;
        any_address_mismatch = true;
        reporter.log("WBCL integrity", "Load address mismatch",
                     "path=" + image.file_name + " tpm=0x" + std::to_string(image.memory_address) +
                     " wbcl=0x" + std::to_string(candidate->memory_address));
      }
    }
    image.wbcl_path_trustworthy = trustworthy_path(image.wbcl_path);
    image.tpm_basename_usable_for_bcd_compare = usable_basename(image.tpm_basename);
    image.skip_bcd_compare = skip_bcd_compare(image.wbcl_path, image.tpm_basename);
    if ((image.wbcl_path_trustworthy || image.tpm_basename_usable_for_bcd_compare) && !image.skip_bcd_compare) {
      image.bcd_match = path_matches(bcd_candidates, image.wbcl_path, image.tpm_basename);
      if (!image.bcd_match) {
        any_bcd_mismatch = true;
        reporter.log("WBCL integrity", "Measured boot vs BCD firmware applications mismatch",
                     "tpm_basename=" + image.tpm_basename + " wbcl_path=" + image.wbcl_path);
      }
    }
  }
  if (any_bcd_mismatch) {
    reporter.console("Boot Tampering Discrepancy [TYPE V]:::Boot instance");
    reporter.log("EFI Boot Check", "Measured boot vs BCD firmware applications mismatch",
                 "bcd_paths=" + std::to_string(bcd_candidates.size()) +
                 " boot_chain=" + std::to_string(measured.boot_chain.size()));
  }
  if (any_address_mismatch) {
    reporter.console("Boot Address Discrepancy [TYPE V]:::Boot instance");
    reporter.log("EFI Boot Check", "TPM vs WBCL load address mismatch",
                 "boot_chain=" + std::to_string(measured.boot_chain.size()));
  }
  for (const auto& image : measured.boot_chain) {
    const auto type = image.drive_type;
    if (type.find("SATA") != ByteString::npos || type.find("NVMe") != ByteString::npos ||
        type.find("Unknown") != ByteString::npos) continue;
    reporter.console(
        "Boot Chain Discrepancy [TYPE V]:::Boot Instance:::Suspicious boot from an EFI file on an uncommon device (" +
        type + ")");
    reporter.log("EFI Boot Check", "Suspicious EFI boot device type",
                 "path=" + image.file_name + " drive_type=" + type);
    break;
  }
}

// Original eESkyNiOov.
void classify_windows_bootloader_presence(const BootEvidence& evidence, Reporter& reporter) {
  const auto& chain = evidence.tpm.boot_chain;
  if (chain.empty()) {
    reporter.log("EFI Boot Check", "Boot chain verdict skipped",
                 "No measured-boot evidence from TPM or WBCL fallback; skipping Windows-bootloader presence check.");
    return;
  }
  for (const auto& image : chain)
    if (basename(image.file_name).find("bootmgfw.efi") != ByteString::npos) return;
  reporter.console("Generic EFI Modification [TYPE V3]:::Boot instance:::Refer to the Boot Sequence tab");
  const auto source = (!evidence.tpm.boot_chain_from_wbcl && evidence.tpm.available) ? "tpm" : "wbcl";
  reporter.log("EFI Boot Check", "No Windows bootloader in boot chain",
               "chain_len=" + std::to_string(chain.size()) + " source=" + source);
}

// Original (*UmPHDaJBohYX).jOMDly.
std::vector<ByteString> gpt_count_anomalies(const MeasuredBootState& measured) {
  if (measured.gpt_count_pcr5 < 2) return {};
  return {"[SUSPICIOUS] Multiple events detected (found: " +
          std::to_string(measured.gpt_count_pcr5) + ")"};
}
}
