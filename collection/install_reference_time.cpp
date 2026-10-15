#include "../lua/query_records.hpp"
#include <functional>
#include <cstring>
namespace ocean::reconstructed::install_reference_time_review {
// Recovered: gather ordered registry/file timestamps, select a reference through
// recovered flag/name priority and clustering rules, cache it with Sync.Once,
// and expose formatted install/factory-reset ages. Invalid providers are skipped.
using ByteString = lua_review::ByteString;
using GoTimeWords = lua_review::GoTimeWords;
struct TimeCandidate { // original3759d80,48 bytes
    ByteString source;
    GoTimeWords time;
    bool flag40 = false, flag41 = false, flag42 = false;
};
struct ReferenceTime { // Ee returns40 bytes: Time24 +source-descriptionSTRING16
    GoTimeWords time;
    ByteString source;
};
struct CachedReferenceGlobals {
    std::uint32_t original_once_done = 0; // 577a8b0
    ReferenceTime result;                 // time572e980/988/990; source572b9e0/9e8
};
struct CandidateCollectionGlobals {
    ByteString user_profile_component; // 572b7f0/7f8, used below C:\Users
    ByteString user_sid_component;     // 572b7e0/7e8, used below C:\$Recycle.BIN
};
struct NativeTimeResult {
    GoTimeWords time;
    lua_review::QueryError error;
};
struct ReferenceTimeContracts {
    struct ClusterResult {
        ReferenceTime reference;
        bool found = false;
    };
    virtual ~ReferenceTimeContracts() = default;
    virtual void original_once_do(CachedReferenceGlobals &, const std::function<void()> &) = 0;
    virtual CandidateCollectionGlobals original_candidate_collection_globals() = 0;
    virtual NativeTimeResult original_registry_install_time() = 0; // xaHr9b@f2c560
    virtual NativeTimeResult original_registry_install_date() = 0; // azmMzikBOI@f2be20
    virtual NativeTimeResult original_file_creation_time(const ByteString &) = 0; // axRr9G5@f2bc80
    virtual lua_review::QueryError
    original_user_directory_query(ByteString &) = 0;                  // os.B8QeKR5_BY@1fc640
    virtual ByteString original_windows_base(const ByteString &) = 0; // aC6.FAq5@1d6bc0
    virtual ByteString original_windows_path_join(const std::vector<ByteString> &) = 0;
    virtual GoTimeWords original_time_now() = 0;
    virtual std::int64_t original_time_year(GoTimeWords) = 0;
    virtual GoTimeWords original_time_add_ns(GoTimeWords, std::int64_t) = 0;
    virtual bool original_time_after(GoTimeWords, GoTimeWords) = 0;
    virtual std::int64_t original_time_sub_ns(GoTimeWords, GoTimeWords) = 0;
    virtual bool original_time_before(GoTimeWords, GoTimeWords) = 0;
    [[noreturn]] virtual void original_panic_bounds() = 0;
    virtual void
    original_go_sort_slice(std::vector<TimeCandidate> &,
                           const std::function<bool(std::uint64_t, std::uint64_t)> &) = 0;
    virtual void original_go_sort_strings(std::vector<ByteString> &) = 0;
    virtual ByteString original_timed_string_scope(const ByteString &label,
                                                   const std::function<ByteString()> &) = 0;
    virtual ByteString original_time_format(GoTimeWords, const ByteString &layout) = 0;
    virtual std::int64_t original_time_since_ns(GoTimeWords) = 0;
    virtual void log_original_three_strings(const ByteString &label, const ByteString &source,
                                            const ByteString &formatted) = 0;
};
// Recovered rUlcB4oHT0KF@f27440: source labels, order, paths, and three flag bytes were
// captured from original builder instructions with inert provider results.
std::vector<TimeCandidate>
gather_install_time_candidates(ReferenceTimeContracts &r,
                               const CandidateCollectionGlobals &globals) {
    std::vector<TimeCandidate> candidates;
    const auto add = [&](const ByteString &name, const NativeTimeResult &result, bool preferred,
                         bool registry, bool user) {
        if (!result.error)
            candidates.push_back({name, result.time, preferred, registry, user});
    };
    add("InstallTime", r.original_registry_install_time(), false, true, false);
    add("InstallDate", r.original_registry_install_date(), false, true, false);
    struct Artifact {
        const char *path;
        const char *name;
        bool preferred;
    };
    const Artifact artifacts[] = {
        {"C:\\Windows\\Prefetch", "Prefetch", false},
        {"C:\\Windows\\appcompat\\Programs\\Amcache.hve", "Amcache", false},
        {"C:\\Windows\\System32\\sru\\SRUDB.dat", "SRUDB", false},
        {"C:\\Windows\\System32\\config\\SYSTEM", "HiveSYSTEM", false},
        {"C:\\Windows\\System32\\config\\SOFTWARE", "HiveSOFTWARE", false},
        {"C:\\Windows\\System32\\config\\SAM", "HiveSAM", false},
        {"C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "System.evtx", false},
        {"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "Security.evtx", false},
        {"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-ResetEng%4Operational.evtx",
         "ResetEngine", true},
        {"C:\\$SysReset", "SysReset", true},
        {"C:\\Windows\\Logs\\Reset", "ResetLogs", true}};
    for (const auto &artifact : artifacts)
        add(artifact.name, r.original_file_creation_time(artifact.path), artifact.preferred, false,
            false);
    auto profile_component = globals.user_profile_component;
    if (profile_component.empty()) {
        ByteString directory;
        if (!r.original_user_directory_query(directory))
            profile_component = r.original_windows_base(directory);
    }
    if (!profile_component.empty()) {
        const auto profile = r.original_windows_path_join({"C:\\Users", profile_component});
        add("UserProfile", r.original_file_creation_time(profile), false, false, true);
        const auto ntuser = r.original_windows_path_join({profile, "NTUSER.DAT"});
        add("NTUSER", r.original_file_creation_time(ntuser), false, false, true);
    }
    const auto recycle =
        r.original_windows_path_join({"C:\\$Recycle.BIN", globals.user_sid_component});
    add("RecycleSID", r.original_file_creation_time(recycle), false, false, true);
    return candidates; // zero times are kept here; selector filters them later
}
bool zero_time(GoTimeWords t) { return t.wall == 0 && t.ext == 0; }
ReferenceTime reference_from(const TimeCandidate &c) { return {c.time, c.source}; }
// Recovered: NEG64 preserves the original overflow at INT64_MIN; ordinary abs() would
// invoke C++ undefined behavior or silently change this edge case.
std::int64_t original_wrapping_abs(std::int64_t value) {
    if (value >= 0)
        return value;
    const auto bits = std::uint64_t(0) - std::uint64_t(value);
    std::int64_t result = 0;
    std::memcpy(&result, &bits, sizeof result);
    return result;
}
// Original sort comparator closure@f2e4a0, bound to a COPY of clustered rows.
bool candidate_before(ReferenceTimeContracts &r, const std::vector<TimeCandidate> &values,
                      std::uint64_t i, std::uint64_t j) {
    if (i >= values.size())
        r.original_panic_bounds();
    if (j >= values.size())
        r.original_panic_bounds();
    return r.original_time_before(values[i].time, values[j].time);
}
// mTtnW_S8oc@f2db20. Neighbors are withinwindow of an anchor, so the chosen
// cluster can span 2*window. Input rows are not sorted or modified.
ReferenceTimeContracts::ClusterResult
cluster_reference_candidates(ReferenceTimeContracts &r,
                             const std::vector<TimeCandidate> &candidates, std::int64_t window_ns,
                             std::int64_t minimum) {
    if (std::int64_t(candidates.size()) < minimum)
        return {};
    std::size_t best_index = 0, best_count = 0;
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        std::size_t count = 0;
        for (const auto &other : candidates)
            if (original_wrapping_abs(r.original_time_sub_ns(candidates[i].time, other.time)) <=
                window_ns)
                ++count;
        if (count > best_count) {
            best_index = i;
            best_count = count;
        } else if (count == best_count) {
            if (best_index >= candidates.size())
                r.original_panic_bounds();
            if (r.original_time_after(candidates[i].time, candidates[best_index].time))
                best_index = i;
        }
    }
    if (std::int64_t(best_count) < minimum)
        return {};
    if (best_index >= candidates.size())
        r.original_panic_bounds();
    const auto anchor = candidates[best_index].time;
    std::vector<TimeCandidate> clustered;
    for (const auto &c : candidates)
        if (original_wrapping_abs(r.original_time_sub_ns(anchor, c.time)) <= window_ns)
            clustered.push_back(c);
    r.original_go_sort_slice(clustered,
                             [&](auto i, auto j) { return candidate_before(r, clustered, i, j); });
    std::vector<ByteString> names;
    for (const auto &c : clustered)
        names.push_back(c.source);
    r.original_go_sort_strings(names);         // duplicates retained, originalbytelexical order
    const auto median = clustered.size() >> 1; // uppermedian for even sizes, no averaging
    if (median >= clustered.size())
        r.original_panic_bounds();
    ByteString joined;
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i)
            joined += ",";
        joined += names[i];
    }
    return {{clustered[median].time, "cluster(" + joined + ")"}, true};
}
// mI5r_Jy04@f2cf60. Candidate order matters for equal times and source-name
// fallbacks; no sorting or deduplication is inserted into these branches.
ReferenceTime select_reference_time(ReferenceTimeContracts &r,
                                    const std::vector<TimeCandidate> &candidates) {
    const auto now = r.original_time_now();
    std::vector<TimeCandidate> valid;
    for (const auto &c : candidates) {
        if (zero_time(c.time))
            continue;
        if (r.original_time_year(c.time) < 2006)
            continue;
        if (r.original_time_after(c.time, r.original_time_add_ns(now, 3600000000000LL)))
            continue;
        valid.push_back(c);
    }
    if (valid.empty())
        return {};
    std::vector<TimeCandidate> ordinary;
    for (const auto &c : valid)
        if (!c.flag41 && !c.flag42)
            ordinary.push_back(c);
    const auto clustered = cluster_reference_candidates(r, ordinary, 86400000000000LL, 3);
    if (clustered.found)
        return clustered.reference;
    ReferenceTime preferred;
    for (const auto &c : ordinary)
        if (c.flag40 && r.original_time_after(c.time, preferred.time))
            preferred = reference_from(c);
    if (!zero_time(preferred.time))
        return preferred;
    // Name priority precedes recency and searches every valid candidate, including
    // rows excluded from the ordinary set by flags 41/42. First match wins.
    for (const auto &wanted : {ByteString("InstallTime"), ByteString("InstallDate")})
        for (const auto &c : valid)
            if (c.source == wanted)
                return reference_from(c);
    if (ordinary.empty())
        return reference_from(valid.front());
    auto latest = reference_from(ordinary.front());
    for (std::size_t i = 1; i < ordinary.size(); ++i)
        if (r.original_time_after(ordinary[i].time, latest.time))
            latest = reference_from(ordinary[i]);
    return latest;
}
// EeB6Y7KK_@f273e0; once callback@f53bc0. Original Sync.Once handles
// concurrent callers and marks done even when the callback panics; no reset is added.
ReferenceTime cached_reference_time(ReferenceTimeContracts &r, CachedReferenceGlobals &globals) {
    if (!globals.original_once_done)
        r.original_once_do(globals, [&] {
            const auto candidates =
                gather_install_time_candidates(r, r.original_candidate_collection_globals());
            globals.result = select_reference_time(r, candidates);
        });
    return globals.result;
}
double duration_hours(std::int64_t ns) {
    return double(ns % 3600000000000LL) / 3600000000000.0 + double(ns / 3600000000000LL);
}
// Recovered PPEBuhDdvVhp@f23020: below one minute this emits "<59 sec ago".
ByteString format_reference_age(std::int64_t ns) {
    const double hours = duration_hours(ns);
    const auto days = std::int64_t(hours / 24.0);
    if (days > 0)
        return std::to_string(days) + " days ago";
    const auto whole_hours = std::int64_t(hours);
    if (whole_hours > 0)
        return std::to_string(whole_hours) + " hour/s ago";
    const auto minutes =
        std::int64_t(double(ns % 60000000000LL) / 60000000000.0 + double(ns / 60000000000LL));
    if (minutes > 0)
        return std::to_string(minutes) + " min ago";
    return "<59 sec ago"; // alsonegative durations
}
// Recovered WFAUCwhce_f@f24a40: outgoing InstallDate uses this selected time.
ByteString collect_install_date(ReferenceTimeContracts &r, CachedReferenceGlobals &globals) {
    return r.original_timed_string_scope("Install Date", [&] {
        const auto reference = cached_reference_time(r, globals);
        if (reference.time.wall == 0 && reference.time.ext == 0)
            return ByteString("unknown");
        const auto for_log = r.original_time_format(reference.time, "2006-01-02 15:04:05");
        r.log_original_three_strings("InstallDate", reference.source, for_log);
        return r.original_time_format(reference.time, "2006-01-02 15:04:05"); // secondoriginalcall
    });
}
// Recovered RmPZxSKPcklB@f26520: factory_reset is the age of the same selected time.
ByteString collect_factory_reset_age(ReferenceTimeContracts &r, CachedReferenceGlobals &globals) {
    return r.original_timed_string_scope("Factory Reset", [&] {
        const auto reference = cached_reference_time(r, globals);
        if (reference.time.wall == 0 && reference.time.ext == 0)
            return ByteString("unknown");
        const auto duration = r.original_time_since_ns(reference.time);
        r.log_original_three_strings("FactoryReset", reference.source,
                                     format_reference_age(duration));
        return format_reference_age(duration); // originalcallsPPEtwice; no secondtimequery
    });
}
} // namespace ocean::reconstructed::install_reference_time_review
