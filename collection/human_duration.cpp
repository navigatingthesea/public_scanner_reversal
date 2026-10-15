#include "../session/session_types.hpp"
namespace ocean::reconstructed::human_duration {
// Recovered: convert signed nanoseconds to one coarse age unit using the original
// floating-point arithmetic. It does not round or combine units; negative values
// and values below one minute produce "<59 sec ago".
ByteString describe(std::int64_t nanoseconds) { // UAy9caHUbZ.PPEBuhDdvVhp@f23020
    constexpr std::int64_t hour_ns = 3600000000000LL, minute_ns = 60000000000LL;
    const double hours =
        double(nanoseconds / hour_ns) + double(nanoseconds % hour_ns) / double(hour_ns);
    const auto days = std::int64_t(hours / 24.0);
    if (days > 0)
        return std::to_string(days) + " days ago";
    const auto whole_hours = std::int64_t(hours);
    if (whole_hours > 0)
        return std::to_string(whole_hours) + " hour/s ago";
    const double minutes =
        double(nanoseconds / minute_ns) + double(nanoseconds % minute_ns) / double(minute_ns);
    const auto whole_minutes = std::int64_t(minutes);
    if (whole_minutes > 0)
        return std::to_string(whole_minutes) + " min ago";
    return "<59 sec ago"; // includes all negative durations and 59.999999999 seconds
}
// 11 original instruction cases include unit boundaries, negatives and INT64_MAX.
// Arithmetic preserves the original floating-point quotient+remainder expression,
// truncation and wording. Guest-only source, never compiled or executed.
} // namespace ocean::reconstructed::human_duration
