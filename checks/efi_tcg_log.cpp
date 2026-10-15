#include "efi_measured_boot.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <sstream>

// Recovered behavior summary:
//   Input: Raw legacy or Event2 TCG log bytes and hashing/baseline providers.
//   Gate: Parses declared digest sizes, selects EFI GPT/application/action events, and classifies
//         PCR0/PCR7 plus the boot chain.
//   Output: Produces ParsedTcgLog images, fingerprints, counts, variables, and anomaly text.
//   Failure: Truncated or unknown structures follow parser rejection/stop paths; measurements are
//            not silently treated as verified disk files.

namespace ocean::checks::efi {
namespace {

constexpr std::uint32_t kEvNoAction = 0x00000003;
constexpr std::uint32_t kEvEfiGptEvent = 0x80000006;
constexpr std::uint32_t kEvEfiBootServicesApplication = 0x80000003;
constexpr std::uint32_t kEvEfiAction = 0x80000007;
constexpr std::uint16_t kAlgSha1 = 0x0004;
constexpr std::uint16_t kAlgSha256 = 0x000B;
constexpr std::uint16_t kAlgSha384 = 0x000C;
constexpr std::uint16_t kAlgSha512 = 0x000D;

const std::array<std::uint8_t, 16> kEfiGlobalVariableGuid{
    0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
    0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C};

std::uint16_t u16(const Bytes& b, std::size_t at) {
    return std::uint16_t(b[at]) | (std::uint16_t(b[at + 1]) << 8);
}
std::uint32_t u32(const Bytes& b, std::size_t at) {
    return std::uint32_t(b[at]) | (std::uint32_t(b[at + 1]) << 8) |
           (std::uint32_t(b[at + 2]) << 16) | (std::uint32_t(b[at + 3]) << 24);
}
std::uint64_t u64(const Bytes& b, std::size_t at) {
    return std::uint64_t(u32(b, at)) | (std::uint64_t(u32(b, at + 4)) << 32);
}
Bytes slice(const Bytes& b, std::size_t at, std::size_t count) {
    return Bytes(b.begin() + at, b.begin() + at + count);
}
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return value;
}
std::string trim(std::string value) {
    auto white = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!value.empty() && (white(value.front()) || value.front() == '\0')) value.erase(value.begin());
    while (!value.empty() && (white(value.back()) || value.back() == '\0')) value.pop_back();
    return value;
}
std::string utf16le(const Bytes& raw) {
    std::string out;
    for (std::size_t i = 0; i + 1 < raw.size(); i += 2) {
        const auto cp = u16(raw, i);
        if (cp < 0x80) out.push_back(char(cp));
        else if (cp < 0x800) { out.push_back(char(0xC0 | (cp >> 6))); out.push_back(char(0x80 | (cp & 0x3F))); }
        else {
            out.push_back(char(0xE0 | (cp >> 12)));
            out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}
std::string hex_upper(const Bytes& bytes) {
    static constexpr char table[] = "0123456789ABCDEF";
    std::string out(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[i * 2] = table[bytes[i] >> 4];
        out[i * 2 + 1] = table[bytes[i] & 15];
    }
    return out;
}
std::string guid(const Bytes& b, std::size_t at) {
    char out[64]{};
    std::snprintf(out, sizeof(out), "%08X-%04X-%04X-%04X-%s",
        u32(b, at), u16(b, at + 4), u16(b, at + 6),
        std::uint16_t((std::uint16_t(b[at + 8]) << 8) | b[at + 9]),
        hex_upper(slice(b, at + 10, 6)).c_str());
    return out;
}
std::string algorithm_name(std::uint16_t id) {
    switch (id) {
        case kAlgSha1: return "SHA1";
        case kAlgSha256: return "SHA256";
        case kAlgSha384: return "SHA384";
        case kAlgSha512: return "SHA512";
        default: { char out[32]{}; std::snprintf(out, sizeof(out), "UNKNOWN(0x%04X)", id); return out; }
    }
}
std::size_t digest_size(std::uint16_t id) {
    switch (id) {
    case kAlgSha1: return 20;
    case kAlgSha256: return 32;
    case kAlgSha384: return 48;
    case kAlgSha512: return 64;
    default: return 0;
    }
}

struct Event {
    std::uint32_t pcr{};
    std::uint32_t type{};
    std::map<std::uint16_t, Bytes> digests;
    Bytes data;
};

bool parse_spec_id(const Bytes& log, std::size_t& offset, std::map<std::uint16_t, std::size_t>& sizes) {
    if (log.size() < 32) return false;
    const auto event_size = u32(log, 28);
    if (!event_size || 32u + event_size > log.size() || event_size < 28) return false;
    static constexpr char signature[] = "Spec ID Event03";
    if (std::memcmp(log.data() + 32, signature, 15) != 0 || log[47] != 0) return false;
    const auto count = u32(log, 56);
    std::size_t cursor = 60;
    for (std::uint32_t i = 0; i < count; ++i) {
        if (cursor + 4 > 32u + event_size) return false;
        sizes[u16(log, cursor)] = u16(log, cursor + 2);
        cursor += 4;
    }
    offset = 32u + event_size;
    return true;
}

bool next_event2(const Bytes& log, std::size_t& cursor, const std::map<std::uint16_t, std::size_t>& sizes, Event& event) {
    if (cursor + 12 > log.size()) return false;
    event = {}; event.pcr = u32(log, cursor); event.type = u32(log, cursor + 4);
    const auto count = u32(log, cursor + 8); cursor += 12;
    for (std::uint32_t i = 0; i < count; ++i) {
        if (cursor + 2 > log.size()) return false;
        const auto id = u16(log, cursor); cursor += 2;
        const auto found = sizes.find(id); if (found == sizes.end() || cursor + found->second > log.size()) return false;
        event.digests[id] = slice(log, cursor, found->second); cursor += found->second;
    }
    if (cursor + 4 > log.size()) return false;
    const auto n = u32(log, cursor); cursor += 4;
    if (cursor + n > log.size()) return false;
    event.data = slice(log, cursor, n); cursor += n; return true;
}

bool next_legacy_event(const Bytes& log, std::size_t& cursor, Event& event) {
    if (cursor + 32 > log.size()) return false;
    event = {}; event.pcr = u32(log, cursor); event.type = u32(log, cursor + 4);
    event.digests[kAlgSha1] = slice(log, cursor + 8, 20);
    const auto n = u32(log, cursor + 28); cursor += 32;
    if (cursor + n > log.size()) return false;
    event.data = slice(log, cursor, n); cursor += n; return true;
}

std::optional<ParsedBootImage> parse_image(const Event& event, Providers& providers) {
    if (event.data.size() < 32) return std::nullopt;
    const auto path_size = u64(event.data, 24);
    if (path_size > event.data.size() - 32) return std::nullopt;
    ParsedBootImage image;
    image.image_location = u64(event.data, 0);
    image.raw_device_path = slice(event.data, 32, std::size_t(path_size));
    const auto identity = providers.decode_device_path(image.raw_device_path);
    image.path = identity.file_path;
    image.partition_guid = identity.partition_guid;
    image.digests = event.digests;
    return image;
}

std::map<std::string, std::string> parse_gpt(const Bytes& event) {
    std::map<std::string, std::string> result;
    if (event.size() < 100) return result;
    const auto disk = guid(event, 0x38);
    const auto count = u32(event, 0x50);
    auto entry_size = u32(event, 0x54);
    if (!entry_size || entry_size > 0x200) entry_size = 0x80;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t start = 100ull + std::size_t(i) * entry_size;
        if (start + 32 > event.size()) break;
        const auto partition = guid(event, start + 16);
        if (partition != "00000000-0000-0000-0000-000000000000") result[partition] = disk;
    }
    return result;
}

void parse_pcr7_variable(Pcr7Measurements& out, const Bytes& data) {
    ++out.total_events; // The original increments before validating the event.
    if (data.size() < 32) return;
    const auto name_size = u64(data, 0); const auto value_size = u64(data, 8);
    if (name_size > data.size() - 32 || value_size > data.size() - 32 - name_size) return;
    if (!std::equal(kEfiGlobalVariableGuid.begin(), kEfiGlobalVariableGuid.end(), data.begin() + 16)) return;
    const auto name = trim(utf16le(slice(data, 32, std::size_t(name_size))));
    const auto value_at = 32u + std::size_t(name_size);
    SecureBootVariable variable{name, std::int64_t(value_size), std::nullopt};
    const bool is_boolean =
        name == "SecureBoot" || name == ".SetupMode" ||
        name == ".AuditMode" || name == ".DeployedMode" ||
        name == ".VendorKeys";
    if (is_boolean && value_size == 1) variable.parsed_boolean = data[value_at] == 1;
    out.variables.push_back(variable);
    if (variable.parsed_boolean) {
        if (name == "SecureBoot") out.secure_boot = *variable.parsed_boolean;
        else if (name == ".SetupMode") out.setup_mode = *variable.parsed_boolean;
        else if (name == ".AuditMode") out.audit_mode = *variable.parsed_boolean;
        else if (name == ".DeployedMode") out.deployed_mode = *variable.parsed_boolean;
        else if (name == ".VendorKeys") out.vendor_keys = *variable.parsed_boolean;
    }
    if (name == "db" || name == "dbx" || name == "PK" || name == "KEK") out.signature_database_measured = true;
}

std::pair<std::string, std::string> read_baseline(Providers& providers) {
    const auto text = providers.read_text_file(providers.state_path("efi_pcr0_state"));
    if (!text) return {};
    std::pair<std::string, std::string> result; // SHA256, SHA1
    std::istringstream lines(*text); std::string line;
    while (std::getline(lines, line)) {
        line = trim(line); const auto split = line.find('='); if (split == std::string::npos) continue;
        const auto key = trim(line.substr(0, split)); const auto value = trim(line.substr(split + 1));
        if (value.size() != 64) continue;
        if (key == "sha256") result.first = value;
        else if (key == "sha1") result.second = value;
    }
    return result;
}

} // namespace

ParsedTcgLog parse_tcg_log(const Bytes& log, Providers& providers) {
    ParsedTcgLog out;
    std::size_t cursor = 0; std::map<std::uint16_t, std::size_t> sizes;
    const bool crypto_agile = parse_spec_id(log, cursor, sizes);
    out.log_format = crypto_agile ? "TCG2" : "TCG1.2";
    if (!crypto_agile) cursor = 0;
    std::map<std::string, std::string> disk_by_partition;
    Event event;
    while (crypto_agile ? next_event2(log, cursor, sizes, event) : next_legacy_event(log, cursor, event)) {
        ++out.total_events;
        if (event.pcr == 0 && event.type != kEvNoAction) {
            ++out.pcr0_event_count;
            if (const auto it = event.digests.find(kAlgSha256);
                it != event.digests.end()) {
                out.concatenated_pcr0_sha256.insert(
                    out.concatenated_pcr0_sha256.end(),
                    it->second.begin(), it->second.end());
            }
            if (const auto it = event.digests.find(kAlgSha1);
                it != event.digests.end()) {
                out.concatenated_pcr0_sha1.insert(
                    out.concatenated_pcr0_sha1.end(),
                    it->second.begin(), it->second.end());
            }
        }
        if (event.pcr == 4 && event.type == kEvEfiBootServicesApplication) {
            if (auto image = parse_image(event, providers)) out.images.push_back(std::move(*image));
        } else if (event.pcr == 5 && event.type == kEvEfiGptEvent) {
            ++out.gpt_event_count;
            for (auto&& [partition, disk] : parse_gpt(event.data)) disk_by_partition[partition] = disk;
        } else if (event.pcr == 7 && event.type == kEvEfiAction) {
            if (!out.pcr7) out.pcr7.emplace();
            parse_pcr7_variable(*out.pcr7, event.data);
        }
    }
    for (auto& image : out.images) {
        if (const auto it = disk_by_partition.find(image.partition_guid);
            it != disk_by_partition.end()) {
            image.disk_guid = it->second;
        }
    }
    return out;
}

void classify_boot_chain(ParsedTcgLog& parsed, Providers& providers) {
    parsed.normal_boot = true; parsed.anomalies.clear();
    if (!parsed.total_events) return;
    if (parsed.images.size() > 1) parsed.normal_boot = false;
    bool windows_loader = false; std::vector<std::string> disks;
    for (const auto& image : parsed.images) {
        const auto name = lower(image.path);
        if (name == "bootmgfw.efi") windows_loader = true;
        else if (name.size() >= 4 && name.substr(name.size() - 4) == ".efi") parsed.normal_boot = false;
        if (!image.disk_guid.empty() &&
            std::find(disks.begin(), disks.end(), image.disk_guid) == disks.end()) {
            disks.push_back(image.disk_guid);
        }
    }
    if (!parsed.images.empty() && !windows_loader) {
        parsed.normal_boot = false;
        parsed.anomalies.push_back("[SUSPICIOUS] No Windows bootloader found in measured boot chain");
    }
    if (disks.size() > 1) {
        parsed.normal_boot = false;
        parsed.anomalies.push_back("[HIGHLY SUSPICIOUS] Multiple disks in boot chain (found: " + std::to_string(disks.size()) + ")");
        providers.console(
            "Boot Disks Anomaly [TYPE V]:::Boot Instance:::Found multiple disks (" +
            std::to_string(disks.size()) +
            ") in boot chain, refer to the Boot sequence tab");
        std::string joined; for (const auto& disk : disks) { if (!joined.empty()) joined += ", "; joined += disk; }
        providers.debug("TPMEfi", "Multiple disks in TPM boot chain", joined);
    }
}

void build_pcr0_summary(ParsedTcgLog& parsed, Providers& providers) {
    if (!parsed.pcr0_event_count) return;
    Pcr0Summary summary; summary.measurement_count = parsed.pcr0_event_count;
    if (!parsed.concatenated_pcr0_sha256.empty()) {
        summary.sha256_fingerprint =
            lower(providers.sha256_hex(parsed.concatenated_pcr0_sha256));
        summary.banks.push_back("SHA256");
    }
    if (!parsed.concatenated_pcr0_sha1.empty()) {
        summary.sha1_fingerprint =
            lower(providers.sha256_hex(parsed.concatenated_pcr0_sha1));
        summary.banks.push_back("SHA1");
    }
    const auto [old256, old1] = read_baseline(providers);
    if (!summary.sha256_fingerprint.empty() && !old256.empty()) {
        summary.baseline_mismatch = summary.sha256_fingerprint != old256;
        if (*summary.baseline_mismatch) {
            summary.previous_fingerprint = old256;
        }
    }
    else if (!summary.sha1_fingerprint.empty() && !old1.empty()) summary.baseline_mismatch = summary.sha1_fingerprint != old1;
    parsed.pcr0 = std::move(summary);
}

void alert_and_persist_pcr0(ParsedTcgLog& parsed, Providers& providers) {
    if (!parsed.pcr0) return;
    const auto& pcr0 = *parsed.pcr0;
    if (pcr0.baseline_mismatch && *pcr0.baseline_mismatch) {
        providers.console(
            "Firmware Fingerprint Change:::Boot instance:::"
            "PCR0 firmware fingerprint changed since previous boot (firmware update, debug mode, or modified firmware)");
        providers.debug(
            "TPMEfi", "PCR0 fingerprint changed between boots",
            "previous=" + pcr0.previous_fingerprint +
                " current=" + pcr0.sha256_fingerprint);
    }
    std::string text;
    if (!pcr0.sha256_fingerprint.empty()) text += "sha256=" + pcr0.sha256_fingerprint + "\n";
    if (!pcr0.sha1_fingerprint.empty()) text += "sha1=" + pcr0.sha1_fingerprint + "\n";
    if (!text.empty()) providers.write_text_file(providers.state_path("efi_pcr0_state"), text, 0600);
}

std::string hash_algorithm_name_for_output(std::uint16_t id) { return algorithm_name(id); }
std::string hex_for_output(const Bytes& data) { return hex_upper(data); }

} // namespace ocean::checks::efi
