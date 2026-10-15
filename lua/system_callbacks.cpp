#include "query_records.hpp"

namespace ocean::reconstructed::lua_review {
std::int64_t original_unix_seconds(GoTimeWords);

struct UserRecord { // @0x3783400, 80 bytes
    ByteString username;
    ByteString full_name;
    bool enabled = false;
    bool locked = false;
    bool admin = false;
    bool password_never_expires = false;
    std::int64_t password_age_days = 0;
    ByteString last_logon;
    std::int64_t last_logon_ts = 0;
    std::uint32_t number_of_logons = 0;
};
struct CollectedUser {
    UserRecord copied_fields;
    std::int64_t password_age_nanoseconds = 0;
    GoTimeWords last_logon;
};
struct ConnectionRecord { // @0x3778940, 104 bytes
    std::int32_t pid = 0;
    ByteString family;
    ByteString type;
    ByteString status;
    ByteString laddr;
    std::uint32_t lport = 0;
    ByteString raddr;
    std::uint32_t rport = 0;
};
struct CollectedConnection { // native 112 bytes: family@4, type@8, PID@104
    std::int32_t pid = 0;
    std::uint32_t family = 0;
    std::uint32_t type = 0;
    ByteString status;
    ByteString laddr;
    ByteString raddr;
    std::uint32_t lport = 0;
    std::uint32_t rport = 0;
};
struct HostInfoRecord { // @0x3786f20, 160 bytes
    ByteString hostname;
    ByteString os;
    ByteString platform;
    ByteString platform_family;
    ByteString platform_version;
    ByteString kernel_version;
    ByteString virtualization_system;
    ByteString virtualization_role;
    std::uint64_t uptime = 0;
    ByteString boot_time;
    std::uint64_t procs = 0;
};
struct CollectedHost {
    HostInfoRecord copied_fields;
    std::uint64_t boot_unix_seconds = 0;
};

struct SystemCallbackContracts {
    using State = std::uint64_t;
    using Value = std::uint64_t;
    virtual ~SystemCallbackContracts() = default;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual ByteString trim_space(const ByteString&) = 0;
    virtual ByteString lower_string(const ByteString&) = 0;
    virtual QueryError collect_users(std::vector<CollectedUser>&) = 0;
    virtual QueryError collect_connections(
        const ByteString& kind,
        std::vector<CollectedConnection>&) = 0;
    virtual QueryError collect_host_info(CollectedHost&) = 0;
    virtual QueryError collect_smb_shares(
        const ByteString& server, Value&) = 0;
    virtual ByteString original_user_last_logon_format(GoTimeWords) = 0; // layout@func12
    virtual ByteString original_host_boot_time_format(std::uint64_t) = 0;
    virtual ByteString connection_family_name(std::uint32_t) = 0;
    virtual ByteString unknown_connection_type_format(std::uint32_t) = 0;
    virtual std::int64_t push_users(State, const std::vector<UserRecord>&) = 0;
    virtual std::int64_t push_connections(
        State, const std::vector<ConnectionRecord>&) = 0;
    virtual std::int64_t push_host_info(State, const HostInfoRecord&) = 0;
    virtual std::int64_t push_original_value(State, Value) = 0;
    virtual std::int64_t push_original_system_error(
        State, std::uint32_t callback, const QueryError&, unsigned branch) = 0;
    virtual QueryError invalid_connection_kind_error(const ByteString&) = 0;
    virtual QueryError missing_smb_server_error() = 0;
};

// @0x1f3c980
std::int64_t users_callback(
    SystemCallbackContracts& runtime,
    SystemCallbackContracts::State state) {
    std::vector<CollectedUser> collected;
    const auto error = runtime.collect_users(collected);
    if (error)
        return runtime.push_original_system_error(state, 0x1f3c980, error, 0);

    std::vector<UserRecord> rows;
    rows.reserve(collected.size());
    for (const auto& user : collected) {
        auto row = user.copied_fields;
        // Go signed division truncates toward zero.
        row.password_age_days =
            user.password_age_nanoseconds / INT64_C(86400000000000);
        row.last_logon.clear();
        row.last_logon_ts = 0;
        if (user.last_logon.wall != 0 || user.last_logon.ext != 0) {
            row.last_logon = runtime.original_user_last_logon_format(user.last_logon);
            row.last_logon_ts = original_unix_seconds(user.last_logon);
        }
        rows.push_back(row);
    }
    return runtime.push_users(state, rows);
}

// @0x1f3d000
std::int64_t connections_callback(
    SystemCallbackContracts& runtime,
    SystemCallbackContracts::State state) {
    auto kind = runtime.lower_string(
        runtime.trim_space(runtime.to_string(state, 1)));
    if (kind.empty()) kind = "all";

    if (kind != "all" && kind != "tcp" && kind != "udp" &&
        kind != "tcp4" && kind != "tcp6" &&
        kind != "udp4" && kind != "udp6") {
        return runtime.push_original_system_error(
            state, 0x1f3d000, runtime.invalid_connection_kind_error(kind), 0);
    }

    std::vector<CollectedConnection> collected;
    const auto error = runtime.collect_connections(kind, collected);
    if (error)
        return runtime.push_original_system_error(state, 0x1f3d000, error, 1);

    std::vector<ConnectionRecord> rows;
    rows.reserve(collected.size());
    for (const auto& connection : collected) {
        ConnectionRecord row;
        row.pid = connection.pid;
        row.family = runtime.connection_family_name(connection.family);
        if (connection.type == 1)
            row.type = "tcp";
        else if (connection.type == 2)
            row.type = "udp";
        else
            row.type = runtime.unknown_connection_type_format(connection.type);
        row.status = connection.status;
        row.laddr = connection.laddr;
        row.lport = connection.lport;
        row.raddr = connection.raddr;
        row.rport = connection.rport;
        rows.push_back(row);
    }
    return runtime.push_connections(state, rows);
}

// @0x1f3ffa0
std::int64_t host_info_callback(
    SystemCallbackContracts& runtime,
    SystemCallbackContracts::State state) {
    CollectedHost collected;
    const auto error = runtime.collect_host_info(collected);
    if (error)
        return runtime.push_original_system_error(state, 0x1f3ffa0, error, 0);

    auto row = collected.copied_fields;
    row.boot_time.clear();
    if (collected.boot_unix_seconds != 0) {
        row.boot_time = runtime.original_host_boot_time_format(
            collected.boot_unix_seconds);
    }
    return runtime.push_host_info(state, row);
}

// @0x1f3eca0
std::int64_t list_smb_shares_callback(
    SystemCallbackContracts& runtime,
    SystemCallbackContracts::State state) {
    const auto server = runtime.trim_space(runtime.to_string(state, 1));
    if (server.empty()) {
        return runtime.push_original_system_error(
            state, 0x1f3eca0, runtime.missing_smb_server_error(), 0);
    }

    SystemCallbackContracts::Value rows = 0;
    const auto error = runtime.collect_smb_shares(server, rows);
    if (error)
        return runtime.push_original_system_error(state, 0x1f3eca0, error, 1);
    return runtime.push_original_value(state, rows);
}

// Users transforms password age to days and emits last-logon fields only for a
// nonzero Go time. Connections validates kind before collection, maps type 1/2
// to tcp/udp, and formats other numeric types. HostInfo copies selected provider
// fields and leaves zero boot time blank. ListSmbShares requires a nonblank server;
// it never silently substitutes localhost. Collector errors retain branch IDs.
}
