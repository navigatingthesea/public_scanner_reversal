#pragma once

// Recovered behavior summary:
//   Input: Provider boundary and semantic records for TBS/TCG measured-boot collection.
//   Gate: The declared helpers classify boot-chain images and PCR0/PCR7 summaries from
//         provider-supplied data.
//   Output: Exposes the readable measured-boot model used by the implementation files.
//   Failure: Windows, registry, hashing, persistence, and reporting operations stay behind
//            Providers.

// Readable reconstruction of the program's TPM/EFI measured-boot collector.
// It is documentation-grade source. Provider calls stand in for the Go runtime,
// Windows registry wrappers, TBS DLL calls, logging, and console reporting.

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ocean::checks::efi {

using Bytes = std::vector<std::uint8_t>;

struct TpmDeviceInfo {
    bool present{};
    std::string version;
    std::uint32_t tbs_tpm_version{};
    std::uint32_t tbs_structure_version{};
    std::string spec_version;
    std::string manufacturer_id;
    std::optional<std::uint32_t> manufacturer_id_raw;
    std::string manufacturer_version;
    std::string physical_presence_version;
    std::string tbs_read_error;
};

struct ParsedBootImage {
    std::string path;
    std::uint64_t image_location{};
    std::string disk_guid;
    std::string partition_guid;
    Bytes raw_device_path;
    std::map<std::uint16_t, Bytes> digests;
};

struct SecureBootVariable {
    std::string name;
    std::int64_t data_length{};
    std::optional<bool> parsed_boolean;
};

struct Pcr7Measurements {
    std::int64_t total_events{};
    std::vector<SecureBootVariable> variables;
    std::optional<bool> secure_boot;
    std::optional<bool> setup_mode;
    std::optional<bool> audit_mode;
    std::optional<bool> deployed_mode;
    std::optional<bool> vendor_keys;
    bool signature_database_measured{};
};

struct Pcr0Summary {
    std::int64_t measurement_count{};
    std::string sha256_fingerprint;
    std::string sha1_fingerprint;
    std::vector<std::string> banks;
    std::optional<bool> baseline_mismatch;
    std::string previous_fingerprint;
};

struct ParsedTcgLog {
    std::vector<ParsedBootImage> images;
    std::int64_t gpt_event_count{};
    bool normal_boot{};
    std::vector<std::string> anomalies;
    std::int64_t total_events{};
    std::string log_format;
    std::optional<Pcr7Measurements> pcr7;
    std::optional<Pcr0Summary> pcr0;
    Bytes concatenated_pcr0_sha256;
    Bytes concatenated_pcr0_sha1;
    std::int64_t pcr0_event_count{};
};

struct DetailedBootImage {
    std::string path;
    std::uint64_t image_location{};
    std::string disk_guid;
    std::string partition_guid;
    std::string device_path_hex;
    std::map<std::string, std::string> digests;
};

struct BootSequenceRow {
    std::size_t index{};
    std::string path;
    std::string partition_prefix;
    std::uint64_t image_location{};
};

struct MeasuredBootResult {
    bool available{};
    TpmDeviceInfo device;
    std::int64_t gpt_event_count{};
    std::int64_t image_count{};
    bool normal_boot{};
    std::string log_format;
    std::int64_t total_events{};
    std::vector<std::string> anomalies;
    std::optional<Pcr7Measurements> pcr7;
    std::optional<Pcr0Summary> pcr0;
    bool boot_chain_from_wbcl{};
    std::vector<DetailedBootImage> images;
    std::vector<BootSequenceRow> boot_sequence;
};

struct DevicePathIdentity {
    std::string file_path;
    std::string partition_guid;
};

struct TbsDeviceInfoRaw {
    std::uint32_t structure_version{};
    std::uint32_t tpm_version{};
    std::uint32_t interface_type{};
    std::uint32_t implementation_revision{};
};

class Providers {
public:
    virtual ~Providers() = default;
    virtual std::optional<TbsDeviceInfoRaw> query_tbs_device_info(std::uint32_t& status) = 0;
    virtual std::optional<Bytes> query_tcg_log_ex(std::uint32_t& status) = 0;
    virtual std::optional<std::string> registry_string(std::string_view path, std::string_view name) = 0;
    virtual std::optional<std::uint32_t> registry_dword(std::string_view path, std::string_view name) = 0;
    virtual DevicePathIdentity decode_device_path(const Bytes& raw) = 0;
    virtual std::string sha256_hex(const Bytes& data) = 0;
    virtual std::optional<std::string> read_text_file(std::string_view path) = 0;
    virtual void write_text_file(std::string_view path, std::string_view text, std::uint32_t mode) = 0;
    virtual std::string state_path(std::string_view leaf) = 0;
    virtual void console(std::string_view message) = 0;
    virtual void debug(std::string_view category, std::string_view message, std::string_view detail) = 0;
};

ParsedTcgLog parse_tcg_log(const Bytes& log, Providers& providers);
void classify_boot_chain(ParsedTcgLog& parsed, Providers& providers);
void build_pcr0_summary(ParsedTcgLog& parsed, Providers& providers);
void alert_and_persist_pcr0(ParsedTcgLog& parsed, Providers& providers);
TpmDeviceInfo collect_tpm_device_info(Providers& providers);
MeasuredBootResult collect_measured_boot(Providers& providers);

} // namespace ocean::checks::efi
