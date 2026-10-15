#include "efi_measured_boot.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

// Recovered behavior summary:
//   Input: TPM registry metadata, Tbsi_GetDeviceInfo, and the two-call TBS event-log API.
//   Gate: Maps captured TPM versions/manufacturer data and parses a returned log only after
//         successful size/data calls.
//   Output: Returns TPM device information and measured-boot evidence.
//   Failure: DLL/procedure, registry, TBS, or parse failures remain error/no-data states rather
//            than fabricated evidence.

namespace ocean::checks::efi {

std::string hash_algorithm_name_for_output(std::uint16_t id);
std::string hex_for_output(const Bytes& data);

namespace {
constexpr std::string_view kTpmRegistry = "SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\AdminDevice";

std::string trim(std::string value) {
    auto white = [](unsigned char c) { return std::isspace(c) != 0 || c == 0; };
    while (!value.empty() && white(value.front())) value.erase(value.begin());
    while (!value.empty() && white(value.back())) value.pop_back();
    return value;
}
std::string first_spec_version(std::string value) {
    if (const auto comma = value.find(','); comma != std::string::npos) value.resize(comma);
    return trim(value);
}
std::string manufacturer_text(std::uint32_t value) {
    std::string text{char(value >> 24), char(value >> 16), char(value >> 8), char(value)};
    for (unsigned char c : text) if (c && (c < 0x20 || c > 0x7E)) return {};
    return trim(text);
}
std::string tpm_version(std::uint32_t value) {
    if (value == 1) return "1.2";
    if (value == 2) return "2.0";
    char out[32]{}; std::snprintf(out, sizeof(out), "unknown(0x%X)", value); return out;
}
void enrich_from_registry(TpmDeviceInfo& out, Providers& providers) {
    if (const auto value = providers.registry_string(kTpmRegistry, "SpecVersion")) {
        out.present = true; out.spec_version = *value;
        if (out.version.empty()) out.version = first_spec_version(*value);
    }
    if (const auto value = providers.registry_dword(kTpmRegistry, "ManufacturerId")) {
        out.present = true; out.manufacturer_id_raw = *value; out.manufacturer_id = manufacturer_text(*value);
        if (out.manufacturer_id.empty()) {
            char text[16]{};
            std::snprintf(text, sizeof(text), "0x%08X", *value);
            out.manufacturer_id = text;
        }
    }
    if (const auto value =
            providers.registry_string(kTpmRegistry, "ManufacturerVersion")) {
        out.present = true;
        out.manufacturer_version = *value;
    }
    if (const auto value =
            providers.registry_string(kTpmRegistry, "PhysicalPresenceVersion")) {
        out.present = true;
        out.physical_presence_version = *value;
    }
}
}

TpmDeviceInfo collect_tpm_device_info(Providers& providers) {
    TpmDeviceInfo out; std::uint32_t status = 0;
    // Original: LoadDLL("Tbs.dll"), FindProc("Tbsi_GetDeviceInfo"), Call(16, &TBS_DEVICE_INFO).
    if (const auto raw = providers.query_tbs_device_info(status)) {
        out.present = true;
        out.tbs_structure_version = raw->structure_version;
        out.tbs_tpm_version = raw->tpm_version;
        out.version = tpm_version(raw->tpm_version);
    } else if (status) {
        char text[64]{}; std::snprintf(text, sizeof(text), "Tbsi_GetDeviceInfo ret=0x%08X", status); out.tbs_read_error = text;
    } else out.tbs_read_error = "Tbs.dll or Tbsi_GetDeviceInfo unavailable";
    enrich_from_registry(out, providers); // The original runs this even when the TBS path fails.
    return out;
}

MeasuredBootResult collect_measured_boot(Providers& providers) {
    MeasuredBootResult out; out.device = collect_tpm_device_info(providers);
    std::uint32_t status = 0;
    // Original two-call contract: Tbsi_Get_TCG_Log_Ex(0, nullptr, &size), then (0, buffer, &size).
    const auto log = providers.query_tcg_log_ex(status);
    if (!log || log->empty()) {
        char detail[96]{}; std::snprintf(detail, sizeof(detail), "ret=0x%08X size=%zu", status, log ? log->size() : 0u);
        providers.debug("TPMEfi", "Tbsi_Get_TCG_Log_Ex size failed or empty", detail); return out;
    }
    auto parsed = parse_tcg_log(*log, providers);
    classify_boot_chain(parsed, providers);
    build_pcr0_summary(parsed, providers);
    alert_and_persist_pcr0(parsed, providers);
    if (!parsed.total_events) {
        providers.debug(
            "TPMEfi", "TCG log produced zero parsed events",
            "log_size=" + std::to_string(log->size()) +
                " format=" + parsed.log_format +
                " - relying on WBCL fallback if available");
    }
    if (parsed.gpt_event_count > 1) {
        providers.console("System Boot Discrepancy [TYPE V]:::Boot instance:::Refer to the Boot Sequence tab");
        providers.debug("TPMEfi", "Multiple EFI GPT events detected", "Found: " + std::to_string(parsed.gpt_event_count));
    }
    out.available = true; out.gpt_event_count = parsed.gpt_event_count; out.image_count = std::int64_t(parsed.images.size());
    out.normal_boot = parsed.normal_boot; out.log_format = parsed.log_format; out.total_events = parsed.total_events;
    out.anomalies = parsed.anomalies; out.pcr7 = parsed.pcr7; out.pcr0 = parsed.pcr0; out.boot_chain_from_wbcl = true;
    for (std::size_t index = 0; index < parsed.images.size(); ++index) {
        const auto& image = parsed.images[index]; DetailedBootImage detailed;
        detailed.path = image.path; detailed.image_location = image.image_location; detailed.disk_guid = image.disk_guid;
        detailed.partition_guid = image.partition_guid; detailed.device_path_hex = hex_for_output(image.raw_device_path);
        for (const auto& [algorithm, digest] : image.digests) {
            detailed.digests[hash_algorithm_name_for_output(algorithm)] =
                hex_for_output(digest);
        }
        out.images.push_back(std::move(detailed));
        out.boot_sequence.push_back({
            index,
            image.path,
            image.partition_guid.substr(
                0, std::min<std::size_t>(8, image.partition_guid.size())),
            image.image_location,
        });
    }
    return out;
}

} // namespace ocean::checks::efi
