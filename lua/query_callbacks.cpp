#include "query_records.hpp"
#include <cstring>

namespace ocean::reconstructed::lua_review {
struct QueryCallbackContracts {
    using State = std::uint64_t;
    using Process = std::uint64_t;
    using Key = std::uint64_t;
    struct FileStat {
        GoTimeWords modification_time;
        bool has_exact_windows_attribute_type = false;
        std::uint32_t creation_low = 0;
        std::uint32_t creation_high = 0;
    };

    virtual ~QueryCallbackContracts() = default;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual ByteString trim_space(const ByteString&) = 0;
    virtual std::int64_t to_integer(State, std::int64_t) = 0;
    virtual ByteString path_argument(State, std::int64_t) = 0;
    virtual void push_nil(State) = 0;
    virtual void push_string(State, const ByteString&) = 0;
    virtual void push_integer(State, std::int64_t) = 0;
    virtual std::int64_t push_formatted_error(
        State,
        std::uint32_t original_callback,
        const QueryError&,
        unsigned branch) = 0;
    virtual std::int64_t push_process_records(
        State, const std::vector<ProcessRecord>&) = 0;
    virtual std::int64_t push_registry_records(
        State, const std::vector<RegistryValueRecord>&) = 0;
    virtual std::int64_t push_time_record(State, const TimeRecord&) = 0;
    virtual QueryError enumerate_processes(std::vector<Process>&) = 0; // wT.TyWkjH
    virtual std::int32_t pid(Process) = 0;
    virtual QueryError process_name(Process, ByteString&) = 0;
    virtual QueryError process_executable(Process, ByteString&) = 0;
    virtual QueryError process_command_line(Process, ByteString&) = 0;
    virtual QueryError process_parent(Process, std::int32_t&) = 0;
    virtual QueryError process_username(Process, ByteString&) = 0;
    virtual QueryError process_created_milliseconds(Process, std::int64_t&) = 0;
    virtual ByteString format_unix_seconds_in_original_local_zone(
        std::int64_t,
        const ByteString&) = 0;
    virtual QueryError parse_registry_path(
        const ByteString&,
        Key& hive,
        ByteString& subkey) = 0; // @0x1f0ed00
    virtual QueryError open_registry_key(
        Key hive,
        const ByteString& subkey,
        std::uint32_t access,
        Key&) = 0;
    virtual void close_registry_key(Key) = 0;
    virtual QueryError read_registry_value_names(
        Key, std::int64_t limit, std::vector<ByteString>&) = 0;
    virtual QueryError read_registry_subkey_names(
        Key, std::int64_t limit, std::vector<ByteString>&) = 0;
    virtual std::int64_t push_string_records(
        State, const std::vector<ByteString>&, bool nonnil) = 0;
    virtual QueryError read_registry_value(
        Key, const ByteString&, RegistryValueRecord&) = 0; // @0x1f10bc0
    virtual QueryError stat_file(const ByteString&, FileStat&) = 0;
    virtual GoTimeWords boot_time_override() = 0; // globals 0x572e0c0/c8/d0
    virtual GoTimeWords collected_boot_time() = 0; // globals 0x572ef80/88/90
    virtual TimeRecord format_original_time_record(GoTimeWords) = 0; // @0x1f17d80
    virtual QueryError original_missing_boot_time_error() = 0;
};

// @0x1f39e40
std::int64_t processes_callback(
    QueryCallbackContracts& runtime,
    QueryCallbackContracts::State state) {
    std::vector<QueryCallbackContracts::Process> processes;
    const auto error = runtime.enumerate_processes(processes);
    if (error)
        return runtime.push_formatted_error(state, 0x1f39e40, error, 0);

    std::vector<ProcessRecord> rows;
    rows.reserve(processes.size());
    for (const auto process : processes) {
        ProcessRecord row;
        row.pid = runtime.pid(process);
        // Recovered: per-field errors are discarded; partial rows remain.
        (void)runtime.process_name(process, row.name);
        (void)runtime.process_executable(process, row.exe);
        (void)runtime.process_command_line(process, row.cmdline);
        (void)runtime.process_parent(process, row.ppid);
        (void)runtime.process_username(process, row.user);

        std::int64_t created_milliseconds = 0;
        const auto time_error = runtime.process_created_milliseconds(
            process, created_milliseconds);
        if (!time_error && created_milliseconds > 0) {
            row.timestamp = created_milliseconds / 1000;
            row.created = runtime.format_unix_seconds_in_original_local_zone(
                row.timestamp, "2006-01-02T15:04:05Z07:00");
        }
        rows.push_back(row);
    }
    return runtime.push_process_records(state, rows);
}

std::uint32_t registry_access_mask(std::int64_t view) {
    if (view == 32) return 0x20219;
    if (view == 64) return 0x20119;
    return 0x20019;
}

// @0x1f23340
std::int64_t read_registry_key_callback(
    QueryCallbackContracts& runtime,
    QueryCallbackContracts::State state) {
    const auto path = runtime.trim_space(runtime.to_string(state, 1));
    const auto view = runtime.to_integer(state, 2);

    QueryCallbackContracts::Key hive = 0;
    QueryCallbackContracts::Key key = 0;
    ByteString subkey;
    auto error = runtime.parse_registry_path(path, hive, subkey);
    if (error) {
        runtime.push_nil(state);
        runtime.push_string(state, *error);
        return 2;
    }

    error = runtime.open_registry_key(
        hive, subkey, registry_access_mask(view), key);
    if (error)
        return runtime.push_formatted_error(state, 0x1f23340, error, 1);
    struct CloseKey {
        QueryCallbackContracts& runtime;
        QueryCallbackContracts::Key key;
        ~CloseKey() { runtime.close_registry_key(key); }
    } close{runtime, key};

    std::vector<ByteString> names;
    error = runtime.read_registry_value_names(key, -1, names);
    if (error)
        return runtime.push_formatted_error(state, 0x1f23340, error, 2);

    std::vector<RegistryValueRecord> rows;
    rows.reserve(names.size());
    for (const auto& name : names) {
        RegistryValueRecord value;
        if (!runtime.read_registry_value(key, name, value))
            rows.push_back(value);
    }
    return runtime.push_registry_records(state, rows);
}

// @0x1f46de0
std::int64_t list_registry_keys_callback(
    QueryCallbackContracts& runtime,
    QueryCallbackContracts::State state) {
    const auto path = runtime.trim_space(runtime.to_string(state, 1));
    const auto view = runtime.to_integer(state, 2);

    QueryCallbackContracts::Key hive = 0;
    QueryCallbackContracts::Key key = 0;
    ByteString subkey;
    auto error = runtime.parse_registry_path(path, hive, subkey);
    if (error)
        return runtime.push_formatted_error(state, 0x1f46de0, error, 0);

    error = runtime.open_registry_key(
        hive, subkey, registry_access_mask(view), key);
    if (error)
        return runtime.push_formatted_error(state, 0x1f46de0, error, 1);
    struct CloseKey {
        QueryCallbackContracts& runtime;
        QueryCallbackContracts::Key key;
        ~CloseKey() { runtime.close_registry_key(key); }
    } close{runtime, key};

    std::vector<ByteString> names;
    error = runtime.read_registry_subkey_names(key, -1, names);
    if (error)
        return runtime.push_formatted_error(state, 0x1f46de0, error, 2);

    // Recovered: allocate a distinct, nonnil []string even when no names exist.
    const std::vector<ByteString> copy = names;
    return runtime.push_string_records(state, copy, true);
}

// Machine @0x1f3627e: time.Time.Unix, including packed-wall branch.
std::int64_t original_unix_seconds(GoTimeWords time) {
    std::uint64_t seconds = static_cast<std::uint64_t>(time.ext);
    if (time.wall & (UINT64_C(1) << 63))
        seconds = ((time.wall << 1) >> 31) + UINT64_C(0xdd7b17f80);
    seconds -= UINT64_C(0xe7791f700);

    std::int64_t signed_seconds;
    std::memcpy(&signed_seconds, &seconds, 8);
    return signed_seconds;
}

// @0x1f361d9: read both FILETIME DWORDs and preserve uint64 wrapping.
std::int64_t original_creation_filetime_seconds(
    std::uint32_t low,
    std::uint32_t high) {
    const std::uint64_t ticks = (std::uint64_t{high} << 32) | low;
    const std::uint64_t nanosecond_bits =
        ticks * 100 + UINT64_C(0x5e6684f4b3960000);
    if (nanosecond_bits < 1000000000) return 0;

    std::int64_t nanoseconds;
    std::memcpy(&nanoseconds, &nanosecond_bits, 8);
    auto seconds = nanoseconds / 1000000000;
    if (nanoseconds % 1000000000 < 0) --seconds;
    return seconds;
}

// @0x1f360a0
std::int64_t last_write_callback(
    QueryCallbackContracts& runtime,
    QueryCallbackContracts::State state) {
    QueryCallbackContracts::FileStat info;
    const auto error = runtime.stat_file(runtime.path_argument(state, 1), info);
    runtime.push_integer(
        state, error ? 0 : original_unix_seconds(info.modification_time));
    return 1;
}

// @0x1f36160
std::int64_t created_at_callback(
    QueryCallbackContracts& runtime,
    QueryCallbackContracts::State state) {
    QueryCallbackContracts::FileStat info;
    if (runtime.stat_file(runtime.path_argument(state, 1), info)) {
        runtime.push_integer(state, 0);
        return 1;
    }

    const auto seconds = info.has_exact_windows_attribute_type ?
        original_creation_filetime_seconds(info.creation_low, info.creation_high) :
        original_unix_seconds(info.modification_time);
    runtime.push_integer(state, seconds);
    return 1;
}

// @0x1f1f1a0
std::int64_t boot_time_callback(
    QueryCallbackContracts& runtime,
    QueryCallbackContracts::State state) {
    auto time = runtime.boot_time_override();
    if (time.wall == 0 && time.ext == 0)
        time = runtime.collected_boot_time();
    if (time.wall == 0 && time.ext == 0) {
        return runtime.push_formatted_error(
            state, 0x1f1f1a0, runtime.original_missing_boot_time_error(), 0);
    }
    return runtime.push_time_record(state, runtime.format_original_time_record(time));
}

// Processes emits one row per enumerated process; only top-level enumeration can
// fail the callback. Registry view 32/64 selects WOW64 masks 0x20219/0x20119;
// other values use 0x20019. Individual registry-value read failures are skipped.
// LastWrite/createdAt convert stat failures to integer zero. createdAt uses native
// creation FILETIME only for the exact recovered Windows attribute type; otherwise
// it falls back to ModTime. BootTime prefers a nonzero override, then collected time.
}
