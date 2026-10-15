#include "../lua/query_records.hpp"
#include <functional>
namespace ocean::reconstructed::recycle_bin_review {
// Recovered: stat the user's recycle-bin directory, cache its modification time,
// format its age, and optionally compare it with the boot override. Stat failure
// returns an empty string while preserving the previous cached globals.
using ByteString = lua_review::ByteString;
using GoTimeWords = lua_review::GoTimeWords;
using Error = lua_review::QueryError;
struct RecycleGlobals {
    ByteString user_directory_component; // 572b7e0/7e8; original initializer remains to be reviewed
    ByteString cached_age;               // 572b9d0/9d8, preserved when Stat fails
    GoTimeWords recycle_directory_modified; // 572ef60/68/70
    GoTimeWords boot_override;              // 572e0c0/c8/d0
    std::vector<ByteString> warnings;       // 572e7a0/a8/b0
};
struct RecycleContracts {
    using Channel = std::uint64_t;
    using FileInfo = std::uint64_t;
    struct Panic {
        std::uint64_t type = 0, data = 0;
    };
    virtual ~RecycleContracts() = default;
    virtual ByteString original_timed_string_scope(const std::function<ByteString()> &) = 0;
    virtual Channel buffered_string_channel(std::size_t) = 0;
    virtual void spawn_goroutine(const std::function<void()> &) = 0;
    virtual ByteString receive_string(Channel) = 0;
    virtual void send_string(Channel, const ByteString &) = 0;
    virtual void original_recovery_scope(const std::function<void()> &,
                                         const std::function<void(Panic)> &) = 0;
    virtual void log_original_recovered_panic(const ByteString &label, Panic) = 0;
    virtual ByteString original_windows_path_join(const std::vector<ByteString> &) = 0;
    virtual Error stat(const ByteString &path, FileInfo &) = 0;
    virtual GoTimeWords modification_time(FileInfo) = 0;
    virtual std::int64_t original_time_since_ns(GoTimeWords) = 0;
    virtual bool original_time_after(GoTimeWords, GoTimeWords) = 0;
};
// Go Duration.Minutes/Hours split quotient and remainder before conversion to
// floating point. Preserve that formula; do not introduce rounding to nearest.
double duration_units(std::int64_t ns, std::int64_t unit) {
    return double(ns / unit) + double(ns % unit) / double(unit);
}
ByteString format_recycle_age(std::int64_t ns) {
    if (ns < 60000000000LL)
        return "0 min ago"; // includes future dates/negative duration
    if (ns < 3600000000000LL)
        return std::to_string(std::int64_t(duration_units(ns, 60000000000LL))) + " min ago";
    if (ns < 86400000000000LL)
        return std::to_string(std::int64_t(duration_units(ns, 3600000000000LL))) + " hours ago";
    return std::to_string(std::int64_t(duration_units(ns, 3600000000000LL) / 24.0)) + " days ago";
}
// Worker@f19d80; recovery@f1b7c0. A failure sends an empty result without
// resetting the cached age or modification time. No channel close is added.
void recycle_bin_worker(RecycleContracts &r, RecycleGlobals &globals,
                        RecycleContracts::Channel channel) {
    r.original_recovery_scope(
        [&] {
            const auto path = r.original_windows_path_join(
                {"C:\\$RECYCLE.BIN\\", globals.user_directory_component});
            RecycleContracts::FileInfo info = 0;
            if (r.stat(path, info)) {
                r.send_string(channel, "");
                return;
            }
            const auto modified = r.modification_time(info);
            globals.recycle_directory_modified = modified;
            globals.cached_age = format_recycle_age(r.original_time_since_ns(modified));
            if (r.original_time_after(modified, globals.boot_override))
                globals.warnings.push_back("Recycle bin modified:::.:::" + globals.cached_age);
            r.send_string(channel, globals.cached_age);
        },
        [&](RecycleContracts::Panic panic) {
            r.log_original_recovered_panic("RecycleBin", panic);
            r.send_string(channel, "");
        });
}
// Outer@f19c00: one worker and one blocking receive, without a timeout.
ByteString collect_recycle_bin(RecycleContracts &r, RecycleGlobals &globals) {
    return r.original_timed_string_scope([&] {
        const auto channel = r.buffered_string_channel(1);
        r.spawn_goroutine([&r, &globals, channel] { recycle_bin_worker(r, globals, channel); });
        return r.receive_string(channel);
    });
}
} // namespace ocean::reconstructed::recycle_bin_review
