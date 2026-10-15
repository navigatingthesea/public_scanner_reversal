#include "query_records.hpp"
#include <set>

namespace ocean::reconstructed::lua_review {
struct EventContracts {
    using State = std::uint64_t;
    using Value = std::uint64_t;

    virtual ~EventContracts() = default;
    virtual void get_field(State, std::int64_t table, const ByteString&) = 0;
    virtual bool is_table(State, std::int64_t) = 0;
    virtual bool is_number(State, std::int64_t) = 0;
    virtual bool is_string(State, std::int64_t) = 0;
    virtual bool to_boolean(State, std::int64_t) = 0;
    virtual std::int64_t to_integer(State, std::int64_t) = 0;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual ByteString trim_space(const ByteString&) = 0;
    virtual ByteString lower_string(const ByteString&) = 0;
    virtual std::int64_t stack_top(State) = 0;
    virtual void push_nil(State) = 0;
    virtual bool next(State, std::int64_t table) = 0;
    virtual void pop(State, std::int64_t) = 0;
    virtual void push_string(State, const ByteString&) = 0;
    virtual void push_boolean(State, bool) = 0;
    virtual ByteString path_argument(State, std::int64_t) = 0;
    virtual QueryError collect_event_records(
        const ByteString& log,
        const std::optional<std::set<std::int64_t>>& ids,
        std::int64_t maximum,
        bool since_boot,
        const ByteString& provider,
        const ByteString& contains,
        Value& records,
        bool& original_boolean) = 0; // xDGkEfcTUa35@1eeb960
    virtual QueryError marshal_original_event_records(Value, ByteString&) = 0;
    virtual std::int64_t push_original_event_error(
        State,
        const QueryError&,
        bool json_stage) = 0;
};

// avqx@0x1ef1700. Table keys are ignored; numeric values form a unique set.
std::optional<std::set<std::int64_t>> event_id_option(
    EventContracts& runtime,
    EventContracts::State state,
    std::int64_t table,
    const ByteString& key) {
    runtime.get_field(state, table, key);
    std::optional<std::set<std::int64_t>> result;
    if (runtime.is_table(state, -1)) {
        result.emplace();
        const auto stack_index = runtime.stack_top(state);
        runtime.push_nil(state);
        while (runtime.next(state, stack_index)) {
            if (runtime.is_number(state, -1))
                result->insert(runtime.to_integer(state, -1));
            runtime.pop(state, 1);
        }
    }
    runtime.pop(state, 1);
    return result;
}

// n4p@0x1ef1500
std::int64_t integer_option(
    EventContracts& runtime,
    EventContracts::State state,
    std::int64_t table,
    const ByteString& key,
    std::int64_t fallback) {
    runtime.get_field(state, table, key);
    const auto value = runtime.is_number(state, -1) ?
        runtime.to_integer(state, -1) : fallback;
    runtime.pop(state, 1);
    return value;
}

// d6z@0x1ef15c0: Lua truthiness; no IsBoolean gate.
bool boolean_option(
    EventContracts& runtime,
    EventContracts::State state,
    std::int64_t table,
    const ByteString& key) {
    runtime.get_field(state, table, key);
    const auto value = runtime.to_boolean(state, -1);
    runtime.pop(state, 1);
    return value;
}

// wuuz@0x1ef1440: non-string values become empty; strings are TrimSpace'd.
ByteString string_option(
    EventContracts& runtime,
    EventContracts::State state,
    std::int64_t table,
    const ByteString& key) {
    runtime.get_field(state, table, key);
    const auto value = runtime.is_string(state, -1) ?
        runtime.trim_space(runtime.to_string(state, -1)) : ByteString{};
    runtime.pop(state, 1);
    return value;
}

// @0x1f37c00
std::int64_t read_event_log_callback(
    EventContracts& runtime,
    EventContracts::State state) {
    const auto log = runtime.path_argument(state, 1);
    std::optional<std::set<std::int64_t>> ids;
    std::int64_t maximum = 10000;
    bool since_boot = false;
    ByteString provider;
    ByteString contains;

    if (runtime.is_table(state, 2)) {
        ids = event_id_option(runtime, state, 2, "ids");
        const auto requested = integer_option(runtime, state, 2, "max", maximum);
        if (requested > 0) maximum = requested;
        if (maximum > 200000) maximum = 200000;
        since_boot = boolean_option(runtime, state, 2, "sinceboot");
        provider = runtime.lower_string(
            string_option(runtime, state, 2, "provider"));
        contains = runtime.lower_string(
            string_option(runtime, state, 2, "contains"));
    }

    EventContracts::Value records = 0;
    bool result_flag = false;
    auto error = runtime.collect_event_records(
        log, ids, maximum, since_boot, provider, contains, records, result_flag);
    if (error) return runtime.push_original_event_error(state, error, false);

    ByteString encoded;
    error = runtime.marshal_original_event_records(records, encoded);
    if (error) return runtime.push_original_event_error(state, error, true);

    runtime.push_string(state, encoded);
    runtime.push_nil(state);
    runtime.push_boolean(state, result_flag);
    return 3;
}

// Input: log path plus optional ids/max/sinceboot/provider/contains table. `ids`
// is nil when the field is not a table; an empty table remains nonnil. Positive
// max overrides 10,000 and is capped at 200,000; provider and contains are
// trimmed then lowercased. Output is `(JSON,nil,provider_flag)`. Collection and
// JSON failures use distinct original error stages.
}
