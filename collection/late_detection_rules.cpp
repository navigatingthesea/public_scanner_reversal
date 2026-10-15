#include "../../common/review_contracts.hpp"
#include <vector>
#include <algorithm>
namespace ocean::reconstructed {
// Recovered: decode the server-provided LDET payload, inflate its gzip rule map,
// then process keys in sorted order while fetching current values from the map.
// Per-rule decode failures are logged and skipped; normal completion returns nil.
using RuleBytes = std::vector<std::uint8_t>;
struct LateRuleContracts {
    struct GzipReader {
        std::uint64_t opaque;
    };
    struct RuleMap {
        std::uint64_t opaque;
    };
    virtual ~LateRuleContracts() = default;
    virtual void register_common_defer(std::uint64_t descriptor) = 0;
    virtual void register_timing_defer(std::uint64_t owner_rva) = 0;
    virtual ByteString response_LDET() = 0; // shared response global0x5733490, JSON LDET
    virtual ByteString trim_space(const ByteString &) = 0;
    virtual bool decode_standard_base64(const ByteString &, RuleBytes &) = 0;
    virtual bool open_gzip_reader(const RuleBytes &, GzipReader &) = 0;
    virtual void defer_close_gzip_reader(GzipReader) = 0;
    virtual bool decode_json_rule_map(GzipReader, RuleMap &) = 0;
    virtual std::size_t rule_count(RuleMap) = 0;
    virtual std::vector<ByteString> keys_from_original_map_iteration(RuleMap) = 0;
    virtual ByteString current_rule_value(RuleMap, const ByteString &key) = 0;
    virtual void before_rule_loop_helper() = 0; // lbT39TVv8.LmDUPGHQN
    virtual void log_rule_count(std::size_t) = 0;
    virtual void log_rule_start(const ByteString &key) = 0;
    // Original rule helper aUshQ9KbD.heczHe @0x1f0a560.
    virtual ByteString process_rule_payload(const RuleBytes &, const ByteString &key,
                                            std::uint64_t callback_descriptor, bool mode) = 0;
    virtual void log_rule_processing_result(const ByteString &key, const ByteString &error) = 0;
    virtual void log_rule_decode_error(const ByteString &key) = 0;
    virtual void run_registered_defers() = 0;
};
// aUshQ9KbD.Zkq6zon76 @0x1f086c0. It always returns a nil Go error
// on normal completion; per-rule failures are logged and later rules continue.
// Map iteration/mutation and error/interface behavior remain original contracts.
void process_encoded_rule_map(LateRuleContracts &r, LateRuleContracts::RuleMap map, bool mode) {
    if (r.rule_count(map) == 0)
        return;
    r.before_rule_loop_helper();
    auto keys = r.keys_from_original_map_iteration(map);
    std::sort(keys.begin(), keys.end());
    r.log_rule_count(keys.size());
    const auto callback = mode ? 0x3dfeeb0ULL : 0x3dfeeb8ULL;
    for (const auto &key : keys) {
        // Fetch after sorting. Do not freeze the values while enumerating keys.
        const auto encoded = r.current_rule_value(map, key);
        RuleBytes bytes;
        if (!r.decode_standard_base64(encoded, bytes)) {
            r.log_rule_decode_error(key);
            continue;
        }
        r.log_rule_start(key);
        const auto error = r.process_rule_payload(bytes, key, callback, mode);
        r.log_rule_processing_result(key, error);
    }
}
// aUshQ9KbD.CA23IZ @0x1f08060. The recovered664-byte reader fields
// match Go gzip.Reader (Header, CRC/size,512-byte buffer, multistream flag).
// This identifies the format; the exact Go version is not implied.
void process_server_late_detection_rules(LateRuleContracts &r) {
    r.register_common_defer(0x3dfe438);
    r.register_timing_defer(0x1f08060);
    const auto encoded = r.response_LDET();
    // TrimSpace only controls the emptiness check. Decode the ORIGINAL text,
    // as the original does; leading/trailing spaces can still cause a decode error.
    if (r.trim_space(encoded).empty()) {
        r.run_registered_defers();
        return;
    }
    RuleBytes gzip_bytes;
    if (!r.decode_standard_base64(encoded, gzip_bytes) || gzip_bytes.empty()) {
        r.run_registered_defers();
        return;
    }
    LateRuleContracts::GzipReader reader;
    if (!r.open_gzip_reader(gzip_bytes, reader)) {
        r.run_registered_defers();
        return;
    }
    r.defer_close_gzip_reader(reader);
    LateRuleContracts::RuleMap rules;
    if (!r.decode_json_rule_map(reader, rules) || r.rule_count(rules) == 0) {
        r.run_registered_defers();
        return;
    }
    // Instruction call state: four cleared context words, false mode, map in R8.
    // The fifth-word-only HLL call omits the map argument; retain it explicitly.
    process_encoded_rule_map(r, rules, false);
    r.run_registered_defers();
}
} // namespace ocean::reconstructed
