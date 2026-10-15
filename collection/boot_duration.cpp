#include "../../common/review_contracts.hpp"
#include <functional>
namespace ocean::reconstructed {
// Recovered: query the boot record in a worker, convert it to elapsed nanoseconds,
// and return one coarse age label through a capacity-one channel. Query failure or
// a recovered panic sends "Unknown"; the outer receive has no timeout.
struct BootDurationContracts {
    virtual ~BootDurationContracts() = default;
    virtual std::uint64_t new_string_channel(std::size_t buffer_capacity) = 0;
    virtual void spawn(std::function<void()>) = 0;
    virtual ByteString receive_string(std::uint64_t channel) = 0;
    virtual void send_string(std::uint64_t channel, const ByteString &) = 0;
    virtual bool query_boot_record(std::int64_t &unix_seconds) = 0; // Q7oH0ksl.Q6RKhzVIvfGt
    virtual void store_go_time(std::uint64_t rva, std::uint64_t wall, std::int64_t ext,
                               std::uint64_t location_global) = 0;
    virtual std::int64_t nanoseconds_since_stored_boot_time() = 0;
    virtual void directly_deferred_recovery(std::function<void()> body,
                                            std::function<void()> recovery) = 0;
    virtual void log_recovered_panic_for_boot_query() = 0;
    virtual void register_timing_defer(std::uint64_t callback_rva) = 0;
};
// UAy9caHUbZ.mjwnUzZU @0xf37a80. Signed duration arithmetic preserves
// truncation toward zero; output is one unit only, not a complete duration.
ByteString format_boot_age(BootDurationContracts &r, std::int64_t nanoseconds) {
    constexpr std::int64_t day = 86400000000000LL, hour = 3600000000000LL, minute = 60000000000LL;
    const auto days = nanoseconds / day;
    auto remainder = nanoseconds % day;
    const auto hours = remainder / hour;
    const auto minutes = (remainder % hour) / minute;
    if (days >= 1)
        return std::to_string(days) + "d ago";
    if (hours > 0 && days == 0)
        return std::to_string(hours) + "h ago";
    if (minutes > 0 && days == 0 && hours == 0)
        return std::to_string(minutes) + "m ago";
    return "<59s ago";
}
// @0xf382c0, recovery @0xf38400. The deferred closure recovers panics and
// sends "Unknown" after logging; it does not close the channel.
void query_boot_age_worker(BootDurationContracts &r, std::uint64_t channel) {
    r.directly_deferred_recovery(
        [&] {
            std::int64_t unix_seconds;
            if (!r.query_boot_record(unix_seconds)) {
                r.send_string(channel, "Unknown");
                return;
            }
            r.store_go_time(0x572ef80, 0, unix_seconds + 0xe7791f700LL, 0x565c808);
            const auto elapsed = r.nanoseconds_since_stored_boot_time();
            r.send_string(channel, format_boot_age(r, elapsed));
        },
        [&] {
            r.log_recovered_panic_for_boot_query();
            r.send_string(channel, "Unknown");
        });
}
// @0xf38180. Buffered capacity=1; receive has no timeout at this wrapper.
ByteString collect_boot_age(BootDurationContracts &r) {
    r.register_timing_defer(0xf384e0); // original metadata-resolved timing closure
    const auto channel = r.new_string_channel(1);
    r.spawn([&r, channel] { query_boot_age_worker(r, channel); });
    return r.receive_string(channel);
}
} // namespace ocean::reconstructed
