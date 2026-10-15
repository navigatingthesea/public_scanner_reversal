#include "captured_lua_environment.hpp"
#include <vector>

namespace ocean::reconstructed::lua_review {
struct BindingInstallationContracts {
    using State = std::uint64_t;
    using GoMap = std::uint64_t;

    virtual ~BindingInstallationContracts() = default;
    virtual GoMap fresh_flag_map() = 0;
    virtual void begin_json_table(State) = 0;
    virtual void bind_table_field(
        State,
        const ByteString& name,
        std::uint64_t bridge,
        std::uint64_t callback) = 0;
    virtual void publish_json_table(State) = 0;
    virtual void bind_global_function(
        State,
        const ByteString& name,
        std::uint64_t bridge,
        std::uint64_t callback,
        const char* capture_kind,
        std::uint64_t captured_object) = 0;
    virtual std::vector<std::int64_t> current_game_pids() = 0;
    virtual void begin_integer_table(State) = 0;
    virtual void set_integer_pair(State, std::int64_t key, std::int64_t value) = 0;
    virtual void publish_integer_table(State, const ByteString& global_name) = 0;
    virtual void set_global_string(
        State,
        const ByteString& name,
        const ByteString& value) = 0;
};

// t_vaUv2Hp@0x1f128a0 -> o8WAIYHiRT@0x1ee7e20 -> bVJZaiP@0x1ef1820
void install_application_bindings_in_original_order(
    BindingInstallationContracts& runtime,
    BindingInstallationContracts::State state,
    std::uint64_t report_callback) {
    const auto flags = runtime.fresh_flag_map();

    runtime.begin_json_table(state);
    runtime.bind_table_field(state, "decode", 0x1f16360, 0x1f1e700);
    runtime.bind_table_field(state, "encode", 0x1f161c0, 0x1f1e7c0);
    runtime.publish_json_table(state);

    runtime.bind_global_function(state, "print", 0x1f15e40, 0x1f15fe0,
                                 "report callback", report_callback);
    runtime.bind_global_function(state, "oprint", 0x1f159e0, 0x1f15b80,
                                 "report callback", report_callback);
    runtime.bind_global_function(state, "firstbytes", 0x1f15840, 0x1f1ee80,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "drives", 0x1f156a0, 0x1f1ef80,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "journal", 0x1f15500, 0x1f1f020,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "time", 0x1f15360, 0x1f1f0e0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "boottime", 0x1f151c0, 0x1f1f1a0,
                                 "static Go function descriptor", 0);

    runtime.begin_integer_table(state);
    const auto pids = runtime.current_game_pids();
    for (std::size_t index = 0; index < pids.size(); ++index)
        runtime.set_integer_pair(state, static_cast<std::int64_t>(index) + 1, pids[index]);
    runtime.publish_integer_table(state, "GAMEPIDS");

    runtime.bind_global_function(state, "flag", 0x1f14f40, 0x1f150e0,
                                 "per-rule flag map", flags);
    runtime.bind_global_function(state, "IsPe", 0x1f14da0, 0x1f20300,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "PeFile", 0x1f14c00, 0x1f203c0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "get", 0x1f14a60, 0x1f20480,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "GetFiles", 0x1f148c0, 0x1f20540,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "ParsePrefetch", 0x1f14720, 0x1f22620,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "ReadRegKey", 0x1f14580, 0x1f23340,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "readpmem", 0x1f143e0, 0x1f24060,
                                 "static Go function descriptor", 0);

    runtime.bind_global_function(state, "ReadEventLog", 0x1eeb7c0, 0x1f37c00,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "ListEventLogs", 0x1eeb620, 0x1f391a0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "Processes", 0x1eeb480, 0x1f39e40,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "Services", 0x1eeb2e0, 0x1f3ae60,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "InstalledSoftware", 0x1eeb140, 0x1f3be00,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "Users", 0x1eeafa0, 0x1f3c980,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "Connections", 0x1eeae00, 0x1f3d000,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "SmbConnections", 0x1eeac60, 0x1f3eaa0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "ListSmbShares", 0x1eeaac0, 0x1f3eca0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "HostInfo", 0x1eea920, 0x1f3ffa0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "FileInfo", 0x1eea780, 0x1f40b60,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "HashFile", 0x1eea5e0, 0x1f42740,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "FindFiles", 0x1eea440, 0x1f446a0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "ListRegKeys", 0x1eea2a0, 0x1f46de0,
                                 "static Go function descriptor", 0);

    runtime.set_global_string(state, "platform", "windows");
    runtime.bind_global_function(state, "result", 0x1ef30e0, 0x1f33680,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "log", 0x1ef2cc0, 0x1ef2e60,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "lastWrite", 0x1ef2b20, 0x1f360a0,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "createdAt", 0x1ef2980, 0x1f36160,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "FindString", 0x1ef27e0, 0x1ef3280,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "MemStrings", 0x1ef2640, 0x1f36300,
                                 "static Go function descriptor", 0);
    runtime.bind_global_function(state, "ScanPattern", 0x1ef24a0, 0x1f36bc0,
                                 "static Go function descriptor", 0);
}

// Input: a prepared Lua state and the captured report callback descriptor.
// Output: the json table, 36 global functions, GAMEPIDS, and platform string.
// Registration order is exact: GAMEPIDS appears between boottime and flag;
// platform appears before result. This wrapper has no local error path; registry
// behavior and native Lua effects remain contracts.
}
