#include "../lua/query_records.hpp"
#include <limits>

namespace ocean::reconstructed::scan_duration_review {
using ByteString = lua_review::ByteString;

// Recovered equivalent of Go Duration.Round(time.Second): ties round away from
// zero and overflow saturates. The INT64_MIN path never negates the duration.
std::int64_t round_to_seconds(std::int64_t duration) {
    constexpr std::int64_t one_second = 1000000000LL;
    const auto maximum = std::numeric_limits<std::int64_t>::max();
    const auto minimum = std::numeric_limits<std::int64_t>::min();

    if (duration < 0) {
        const auto remainder = -(duration % one_second);
        if (remainder < one_second - remainder) return duration + remainder;

        const auto amount_to_subtract = one_second - remainder;
        if (duration < minimum + amount_to_subtract) return minimum;
        return duration - amount_to_subtract;
    }

    const auto remainder = duration % one_second;
    if (remainder < one_second - remainder) return duration - remainder;

    const auto amount_to_add = one_second - remainder;
    if (duration > maximum - amount_to_add) return maximum;
    return duration + amount_to_add;
}

// C1trGuyj@1f00cc0
ByteString format_scan_duration(std::int64_t duration) {
    constexpr std::int64_t one_second = 1000000000LL;
    constexpr std::int64_t one_minute = 60000000000LL;

    const auto rounded = round_to_seconds(duration);
    // Recovered: retain Go's floating Duration.Seconds/Minutes expression. This
    // matters for a saturated INT64_MAX value that is not a whole second.
    const auto seconds = std::int64_t(
        double(rounded / one_second) +
        double(rounded % one_second) / 1000000000.0);
    if (rounded < one_minute) return std::to_string(seconds) + "s";

    const auto minutes = std::int64_t(
        double(rounded % one_minute) / 60000000000.0 +
        double(rounded / one_minute));
    return std::to_string(minutes) + "m " + std::to_string(seconds % 60) + "s";
}

// Input is a signed nanosecond duration. Output is `<seconds>s` below one minute
// or `<minutes>m <remaining-seconds>s` otherwise. There is no error path.
}
