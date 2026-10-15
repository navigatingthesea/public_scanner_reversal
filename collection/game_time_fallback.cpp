#include "../lua/query_records.hpp"
#include <functional>
#include <cstring>
namespace ocean::reconstructed::game_time_fallback_review {
// Recovered: read Windows InstallDate as a fallback Go time, store it in the
// shared game-time global, then append the live game PID table to the configured
// PID slice. Registry failures yield a zero time without aborting PID appending.
using ByteString = lua_review::ByteString;
using GoTimeWords = lua_review::GoTimeWords;
using Error = lua_review::QueryError;
struct GameTimeGlobals {
    GoTimeWords game_time;                             // 572efa0/fa8/fb0
    std::vector<std::uint64_t> configured_process_ids; // 57321c0/1c8, original8-byte elements
    std::vector<std::uint64_t> live_game_pid_table;    // 572f160/168/170, also exposed to Lua
};
struct InstallTimeContracts {
    using Key = std::uint64_t;
    struct Defers {
        virtual ~Defers() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~InstallTimeContracts() = default;
    virtual GoTimeWords original_go_defer_scope(const std::function<GoTimeWords(Defers &)> &) = 0;
    virtual Error open_registry_key(std::uint64_t hive, const ByteString &path,
                                    std::uint32_t access, Key &) = 0;
    virtual Error registry_integer(Key, const ByteString &name, std::uint64_t &value,
                                   std::uint32_t &kind) = 0;
    virtual void close_registry_key(Key) = 0;
    virtual std::uint64_t
    original_local_time_location() = 0; // global565c808, captured points5731520
    virtual void
    original_timing_scope(const std::function<void()> &) = 0; // LmDUPGHQN.J4zzlapPd.func4
    virtual void original_append_pid_slice(std::vector<std::uint64_t> &,
                                           const std::vector<std::uint64_t> &) = 0;
};
// emOYsPdTs@e2b1a0: Windows InstallDate, NOT a process creation-time query.
GoTimeWords windows_install_time_fallback(InstallTimeContracts &r) {
    return r.original_go_defer_scope([&](InstallTimeContracts::Defers &defers) -> GoTimeWords {
        InstallTimeContracts::Key key = 0;
        if (r.open_registry_key(0x80000002, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 1,
                                key))
            return {};
        defers.add([&r, key] { r.close_registry_key(key); });
        std::uint64_t seconds = 0;
        std::uint32_t kind = 0;
        if (r.registry_integer(key, "InstallDate", seconds, kind))
            return {};
        const std::uint64_t wrapped_ext = seconds + 0xe7791f700ULL;
        std::int64_t ext = 0;
        std::memcpy(&ext, &wrapped_ext, sizeof ext);       // originalADD64 wrap
        return {0, ext, r.original_local_time_location()}; // kind is not validated
    });
}
// LmDUPGHQN@e2a900. Later controller EeB6Y7KK_ replaces this value only when
// its returned time is nonzero, so an install-time fallback can remain.
void seed_game_time_and_append_pid_table(InstallTimeContracts &r, GameTimeGlobals &globals) {
    r.original_timing_scope([&] {
        globals.game_time = windows_install_time_fallback(r); // unconditional, including zero
                                                              // result
        r.original_append_pid_slice(globals.live_game_pid_table, globals.configured_process_ids);
        // No clearing, deduplication, liveness query or error-based filtering here.
    });
}
} // namespace ocean::reconstructed::game_time_fallback_review
