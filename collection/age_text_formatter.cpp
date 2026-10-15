#include "../../common/review_contracts.hpp"
namespace ocean::reconstructed::age_text_review {
// Recovered: input is a signed nanosecond duration. The collector converts it
// through the original floating-point quotient/remainder path and emits exactly
// one days/hours/minutes label; zero and every negative value emit "<59 sec ago".
struct AgeFormatContracts {
    virtual ~AgeFormatContracts() = default;
    virtual ByteString original_sprintf_integer(const ByteString &format, GoInt) = 0;
};
// PPEBuhDdvVhp@f23020. Preserve original quotient/remainder-to-double
// arithmetic before conversion to Go int; do not replace with exact integer
// day/hour thresholds near floating rounding boundaries.
ByteString format_age_nanoseconds(AgeFormatContracts &r, GoInt duration) {
    constexpr GoInt hour = 3600000000000LL, minute = 60000000000LL;
    const double hours = static_cast<double>(duration % hour) / static_cast<double>(hour) +
                         static_cast<double>(duration / hour);
    const auto days = static_cast<GoInt>(hours / 24.0);
    if (days > 0)
        return r.original_sprintf_integer("%d days ago", days);
    const auto whole_hours = static_cast<GoInt>(hours);
    if (whole_hours > 0)
        return r.original_sprintf_integer("%d hour/s ago", whole_hours);
    const double minutes = static_cast<double>(duration % minute) / static_cast<double>(minute) +
                           static_cast<double>(duration / minute);
    const auto whole_minutes = static_cast<GoInt>(minutes);
    if (whole_minutes > 0)
        return r.original_sprintf_integer("%d min ago", whole_minutes);
    return "<59 sec ago"; // also every negative duration, despite the "ago" wording
}
// Evidence:10 original boundary/negative fixtures, static signed division and
// double arithmetic. Original decoding/format/Go allocation stays a contract;
// this C++ is explanatory review text, never compiled or executed.
} // namespace ocean::reconstructed::age_text_review
