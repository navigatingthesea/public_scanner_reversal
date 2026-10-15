#include "query_records.hpp"
#include <functional>

namespace ocean::reconstructed::lua_review {
std::int64_t original_unix_seconds(GoTimeWords);
ByteString extension_of_original_file_name(const ByteString&);

struct FindFileRecord { // @0x3765c80, 72 bytes
    ByteString name;
    ByteString path;
    std::int64_t size = 0;
    bool dir = false;
    ByteString modified;
    std::int64_t timestamp = 0;
};
struct EventLogFileRecord { // @0x3759ca0, 64 bytes
    ByteString name;
    ByteString path;
    std::int64_t size = 0;
    ByteString modified;
    std::int64_t timestamp = 0;
};

struct WalkerCallbackContracts {
    using State = std::uint64_t;
    using Entry = std::uint64_t;
    using Stat = std::uint64_t;
    struct WalkReturn {
        std::uint64_t original_go_error_type = 0;
        std::uint64_t original_go_error_data = 0;
    };
    using Visitor =
        std::function<WalkReturn(const ByteString&, Entry, bool error_is_nonnil)>;

    virtual ~WalkerCallbackContracts() = default;
    virtual ByteString path_argument(State, std::int64_t) = 0;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual ByteString trim_space(const ByteString&) = 0;
    virtual ByteString lower_string(const ByteString&) = 0;
    virtual bool is_table(State, std::int64_t) = 0;
    virtual bool original_boolean_option_with_default(
        State, std::int64_t, const ByteString&, bool) = 0; // lFG9YO@1ef1640
    virtual bool original_boolean_option(
        State, std::int64_t, const ByteString&) = 0; // d6z
    virtual std::int64_t original_integer_option(
        State, std::int64_t, const ByteString&, std::int64_t) = 0; // n4p
    virtual QueryError stat_file(const ByteString&, Stat&) = 0;
    virtual bool stat_is_directory(Stat) = 0;
    virtual bool entry_is_directory(Entry) = 0;
    virtual ByteString entry_name(Entry) = 0;
    virtual QueryError entry_info(Entry, Stat&) = 0;
    virtual std::int64_t stat_size(Stat) = 0;
    virtual GoTimeWords stat_modification_time(Stat) = 0;
    virtual bool original_equal_fold(const ByteString&, const ByteString&) = 0;
    virtual bool original_filepath_match_ignoring_error(
        const ByteString& pattern, const ByteString& name) = 0; // ZBIlSc9
    virtual ByteString original_find_modified_format(GoTimeWords) = 0;
    virtual ByteString original_event_log_modified_format(GoTimeWords) = 0;
    virtual WalkReturn original_stop_walk_error() = 0; // globals 0x572be10/18
    virtual WalkReturn original_skip_directory_error() = 0; // globals 0x572be00/08
    virtual WalkReturn walk_directory(const ByteString&, const Visitor&) = 0;
    virtual ByteString environment_variable(const ByteString&) = 0;
    virtual ByteString join_original_path_parts(const std::vector<ByteString>&) = 0;
    virtual std::int64_t push_find_files(State, const std::vector<FindFileRecord>&) = 0;
    virtual std::int64_t push_event_log_files(
        State, const std::vector<EventLogFileRecord>&) = 0;
    virtual std::int64_t push_original_find_error(
        State, const QueryError&, bool path_was_not_directory) = 0;
};

bool matches_file_name(
    WalkerCallbackContracts& runtime,
    const ByteString& filter,
    bool glob,
    const ByteString& name) { // @0x1f45d40
    if (filter.empty()) return true;
    const auto lower_name = runtime.lower_string(name);
    if (glob)
        return runtime.original_filepath_match_ignoring_error(filter, lower_name);
    return lower_name.find(filter) != ByteString::npos;
}

// @0x1f446a0, visitor @0x1f45880
std::int64_t find_files_callback(
    WalkerCallbackContracts& runtime,
    WalkerCallbackContracts::State state) {
    const auto root = runtime.path_argument(state, 1);
    const auto filter = runtime.lower_string(
        runtime.trim_space(runtime.to_string(state, 2)));
    bool recursive = true;
    bool include_directories = false;
    std::int64_t maximum = 1000;
    if (runtime.is_table(state, 3)) {
        recursive = runtime.original_boolean_option_with_default(
            state, 3, "recursive", true);
        const auto requested = runtime.original_integer_option(state, 3, "max", 1000);
        include_directories = runtime.original_boolean_option(state, 3, "dirs");
        if (requested > 0) maximum = requested;
        if (maximum > 20000) maximum = 20000;
    }

    WalkerCallbackContracts::Stat root_stat = 0;
    const auto error = runtime.stat_file(root, root_stat);
    if (error) return runtime.push_original_find_error(state, error, false);
    if (!runtime.stat_is_directory(root_stat))
        return runtime.push_original_find_error(state, {}, true);

    const bool glob = filter.find_first_of("*?[") != ByteString::npos;
    std::vector<FindFileRecord> rows;
    rows.reserve(128);
    std::int64_t visited = 0;
    const WalkerCallbackContracts::Visitor visitor =
        [&](const ByteString& path,
            WalkerCallbackContracts::Entry entry,
            bool error_is_nonnil) {
            if (error_is_nonnil) return WalkerCallbackContracts::WalkReturn{};

            ++visited;
            if (visited > 300000 ||
                rows.size() >= static_cast<std::size_t>(maximum))
                return runtime.original_stop_walk_error();

            const bool is_root = runtime.original_equal_fold(path, root);
            const bool directory = runtime.entry_is_directory(entry);
            if (directory) {
                if (!recursive && !is_root)
                    return runtime.original_skip_directory_error();
                if (!include_directories || is_root)
                    return WalkerCallbackContracts::WalkReturn{};
            }
            if (!matches_file_name(
                    runtime, filter, glob, runtime.entry_name(entry)))
                return WalkerCallbackContracts::WalkReturn{};

            WalkerCallbackContracts::Stat stat = 0;
            if (runtime.entry_info(entry, stat))
                return WalkerCallbackContracts::WalkReturn{};

            FindFileRecord row;
            row.name = runtime.entry_name(entry);
            row.path = path;
            row.size = runtime.stat_size(stat);
            row.dir = runtime.entry_is_directory(entry);
            row.modified = runtime.original_find_modified_format(
                runtime.stat_modification_time(stat));
            row.timestamp = original_unix_seconds(
                runtime.stat_modification_time(stat));
            rows.push_back(row);
            return WalkerCallbackContracts::WalkReturn{};
        };

    (void)runtime.walk_directory(root, visitor);
    return runtime.push_find_files(state, rows);
}

// @0x1f391a0, visitor @0x1f39920
std::int64_t list_event_logs_callback(
    WalkerCallbackContracts& runtime,
    WalkerCallbackContracts::State state) {
    auto system_root = runtime.environment_variable("SystemRoot");
    if (system_root.empty()) system_root = "C:\\Windows";
    const auto root = runtime.join_original_path_parts(
        {system_root, "System32", "winevt", "Logs"});

    std::vector<EventLogFileRecord> rows;
    rows.reserve(512);
    const WalkerCallbackContracts::Visitor visitor =
        [&](const ByteString& path,
            WalkerCallbackContracts::Entry entry,
            bool error_is_nonnil) {
            if (error_is_nonnil) return WalkerCallbackContracts::WalkReturn{};
            if (rows.size() >= 5000) return runtime.original_stop_walk_error();
            if (runtime.entry_is_directory(entry))
                return WalkerCallbackContracts::WalkReturn{};
            if (!runtime.original_equal_fold(
                    extension_of_original_file_name(runtime.entry_name(entry)),
                    ".evtx"))
                return WalkerCallbackContracts::WalkReturn{};

            WalkerCallbackContracts::Stat stat = 0;
            if (runtime.entry_info(entry, stat))
                return WalkerCallbackContracts::WalkReturn{};

            EventLogFileRecord row;
            row.name = runtime.entry_name(entry);
            row.path = path;
            row.size = runtime.stat_size(stat);
            row.modified = runtime.original_event_log_modified_format(
                runtime.stat_modification_time(stat));
            row.timestamp = original_unix_seconds(
                runtime.stat_modification_time(stat));
            rows.push_back(row);
            return WalkerCallbackContracts::WalkReturn{};
        };

    (void)runtime.walk_directory(root, visitor);
    return runtime.push_event_log_files(state, rows);
}

// FindFiles input is root, lowercased filter, and optional recursive/max/dirs.
// Empty filters match all; filters containing * ? [ use filepath.Match, whose
// errors are ignored. It visits at most 300,000 entries and emits at most 20,000
// rows. Per-entry walk/stat errors and the final WalkDir error are discarded.
// ListEventLogs scans `%SystemRoot%\\System32\\winevt\\Logs`, defaults the root
// to C:\Windows, keeps case-insensitive .evtx files, and emits at most 5,000 rows.
}
