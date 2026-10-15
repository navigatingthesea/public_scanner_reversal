#include "../session/session_types.hpp"
#include <vector>
#include <utility>
namespace ocean::reconstructed::hashed_name_pid_lookup {
// Recovered: linearly search the inventory's current iteration order for an exact
// digest, parse the first matching PID string, and return its numeric value. A
// missing digest returns zero; parse errors are ignored and use the parser value.
struct ParsedInteger {
    std::int64_t value = 0;
    bool error = false;
};
struct Contracts {
    virtual ParsedInteger original_go_atoi_with_wrapped_error(const ByteString &) = 0;
};
std::int64_t lookup(Contracts &rt,
                    const std::vector<std::pair<ByteString, ByteString>> &inventory_iteration,
                    const ByteString &digest) { // UAy9caHUbZ.YDYnaOg7@f23740
    for (const auto &[key, pid_text] : inventory_iteration)
        if (key == digest)
            return rt.original_go_atoi_with_wrapped_error(pid_text).value;
    return 0;
    // Exact byte length/equality, no case folding. Iterator order is the Go map's
    // order, not sorted. A missing/nil map yields0. Numeric parse error ignored;
    // syntax errors yield0, overflow retains INT64_MAX/MIN despite wrapped error.
}
// 15 original routes include map miss, case mismatch, second entry, signed/+,
// whitespace/syntax rejection and both overflow directions. Original internal
// strconv parser and app error wrapper interpreted; error pointer equality is
// modeled for the exact captured comparable-pointer error type. Unknown
// captured maps are never treated as empty. Guest-only, never compiled/run.
} // namespace ocean::reconstructed::hashed_name_pid_lookup
