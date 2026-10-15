#include "../../common/review_contracts.hpp"
#include <optional>
namespace ocean::reconstructed {
// Recovered: publish a numeric progress value to the helper, optional widget,
// first theme map's status message, and optional log file. The returned value is
// only the log Sync error type; most callers discard it.
struct ProgressContracts {
    virtual ~ProgressContracts() = default;
    virtual void write_decimal_progress_to_log(const ByteString &) = 0;
    virtual void original_progress_helper(std::int64_t) = 0; // MdNkL0z.AwiQxtqGdqL
    virtual bool has_progress_widget() = 0;                  // global0x565d240
    virtual void store_widget_fraction(float) = 0;           // widget offset4
    virtual bool theme_map_slice_nonempty() = 0;             // global0x572e9e8
    virtual bool first_theme_map_non_nil() = 0;
    virtual std::optional<ByteString> first_theme_progress_message(const ByteString &key) = 0;
    virtual void set_status_text(const ByteString &) = 0; // EGIdVaS7m0.Cap1bEJfVyE
    virtual bool has_log_file() = 0;                      // global0x5727bc0
    virtual std::uint64_t sync_log_file_error_type() = 0;
};
// aUshQ9KbD.CnZChe3sX @0x1efa020. Return is the log Sync error type;
// controller call sites discard it. Progress messages come from only the FIRST
// theme map, keyed by the decimal percentage string.
std::uint64_t publish_progress(ProgressContracts &r, std::int64_t percent) {
    const auto key = std::to_string(percent); // captured %%d
    r.write_decimal_progress_to_log(key);
    r.original_progress_helper(percent);
    if (r.has_progress_widget()) {
        const auto double_percent = (static_cast<double>(percent) / 100.0) * 100.0;
        float bounded = static_cast<float>(double_percent);
        if (bounded < 0.0f)
            bounded = 0.0f;
        if (bounded > 100.0f)
            bounded = 100.0f;
        r.store_widget_fraction(bounded / 100.0f);
    }
    if (r.theme_map_slice_nonempty() && r.first_theme_map_non_nil()) {
        const auto message = r.first_theme_progress_message(key);
        if (message && !message->empty())
            r.set_status_text(*message);
    }
    return r.has_log_file() ? r.sync_log_file_error_type() : 0;
}
} // namespace ocean::reconstructed
