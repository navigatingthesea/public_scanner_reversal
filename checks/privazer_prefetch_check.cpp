#include "../session/session_types.hpp"

// Recovered behavior summary:
//   Input: Captured prefetch rows and each row's run-time list.
//   Gate: Name must contain privazer after lowercasing; the latest run must be strictly after now
//         minus four days.
//   Output: Emits one warning carrying the count of matching rows.
//   Failure: Rows without times are skipped; count is per row, not unique program or execution.

namespace ocean::reconstructed::privazer_prefetch_review {
struct GoTime {
    std::uint64_t wall = 0;
    std::int64_t ext = 0;
    std::uint64_t location = 0;
};
struct PrefetchInput144 {
    ByteString raw_name_at_16;
    std::vector<GoTime> run_times_at_88; //original Time24 slice88/96/104
};
struct Contracts {
    virtual GoTime original_now() = 0;
    virtual GoTime original_add_duration(const GoTime&, std::int64_t nanoseconds) = 0;
    virtual bool original_time_after(const GoTime&, const GoTime&) = 0;
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
    virtual ByteString original_format_count(GoInt) = 0; //decimal Go fmt %d
    virtual void append_warning(const ByteString&) = 0; //572e7a0 -> WARNINGS
    virtual void original_callback_timing_and_recovery_contract() = 0;
};

// CHFR1G8oI6dJ @ 12ac420. Supplied prefetch rows at global572e100/108/110.
// Native artifact parsing/producer is separate; this check does not read files.
void check_recent_prefetch(Contracts& runtime, const std::vector<PrefetchInput144>& records) {
    const auto cutoff = runtime.original_add_duration(runtime.original_now(), -345600000000000LL);
    GoInt recent_records = 0;
    for (const auto& record : records) {
        const auto lower = runtime.original_unicode_lowercase(record.raw_name_at_16);
        if (lower.find("privazer") == ByteString::npos || record.run_times_at_88.empty()) continue;
        auto latest = record.run_times_at_88.front();
        for (const auto& timestamp : record.run_times_at_88)
            if (runtime.original_time_after(timestamp, latest)) latest = timestamp;
        if (runtime.original_time_after(latest, cutoff)) ++recent_records;
    }
    if (recent_records > 0)
        runtime.append_warning("Privazer recently executed (" +
            runtime.original_format_count(recent_records) + ")");
    runtime.original_callback_timing_and_recovery_contract();
}
// Cutoff is now minus4days in nanoseconds, not midnight or scanner boot time.
// Exact cutoff equality fails; future timestamps also satisfy After. Count is
// matching input rows, not total executions or unique executable names. Rows
// with duplicate names count separately. No extension/base equality gate.
// No per-row path/bytes/hashes or timestamps are appended to this warning.
//11 original fixture paths returned with synthetic clock/comparison/providers.
// Original time monotonic/location/arithmetic, Unicode lowercase, producer and
// panic/timing/logger behavior remain explicit contracts. Never compile/run.
}
