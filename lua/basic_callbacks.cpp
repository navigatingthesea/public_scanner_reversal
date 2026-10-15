#include "captured_lua_environment.hpp"
#include <optional>
#include <set>

namespace ocean::reconstructed::lua_review {
using Error = std::optional<ByteString>;

struct BasicCallbackContracts {
    using State = std::uint64_t;
    using Value = std::uint64_t;
    struct Pattern {
        std::array<std::uint64_t, 6> raw_words;
    };

    virtual ~BasicCallbackContracts() = default;
    virtual std::int64_t argument_count(State) = 0;
    virtual ByteString to_string(State, std::int64_t index) = 0;
    virtual ByteString trim_space(const ByteString&) = 0;
    virtual ByteString lower_string(const ByteString&) = 0;
    virtual ByteString file_path_argument(State, std::int64_t index) = 0; // iaVHiPmq
    virtual ByteString original_object_to_string(State, std::int64_t index) = 0;
    virtual void push_nil(State) = 0;
    virtual void push_string(State, const ByteString&) = 0;
    virtual void push_boolean(State, bool) = 0;
    virtual void push_integer(State, std::int64_t) = 0;
    virtual std::int64_t push_go_value(State, Value) = 0; // uDieBvhHG
    virtual std::int64_t push_error_pair(State, const Error&) = 0; // eRpyJxbWw7x
    virtual Error decode_json_and_push_result(State, const ByteString&) = 0; // vNlkScv
    virtual Value lua_value_as_go_value(State, std::int64_t index) = 0; // kPZrRXt
    virtual Error marshal_json(Value, ByteString&) = 0;
    virtual void report_callback(std::uint64_t descriptor, const ByteString&) = 0;
    virtual void log_original_object_print(const ByteString&) = 0;
    virtual Error read_initial_bytes(
        const ByteString& path,
        std::size_t maximum,
        std::vector<std::uint8_t>&) = 0; // zGBofzzbHl7
    virtual Value integer_bytes_as_go_slice(const std::vector<std::uint8_t>&) = 0;
    virtual Error list_drives(Value&) = 0; // wl0BiZ0bS7U
    virtual Error read_journal_records(const ByteString& drive, Value&) = 0; // vJtYm8.CmUVy4
    virtual Value current_time_record() = 0; // time.Now -> sdD08R_ixq90
    virtual Error inspect_pe_file(const ByteString& path, ByteString&) = 0; // lbT.Vzc7GSbdfm6d
    virtual Error lookup_named_collection(
        const ByteString& normalized_name,
        Value&) = 0; // hm7p3tlQH
    virtual ByteString flag_message(State) = 0; // wsaMXkhmwZ
    virtual ByteString flag_log_suffix() = 0;
    virtual void log_flag(const ByteString&) = 0; // jc_KkjVPX7fY.TYheK4ZApSl3
    virtual void get_global(State, const ByteString&) = 0;
    virtual void get_field(State, std::int64_t index, const ByteString&) = 0;
    virtual void remove_stack_value(State, std::int64_t index) = 0;
    virtual bool is_function(State, std::int64_t index) = 0;
    virtual void pop(State, std::int64_t count) = 0;
    virtual void insert_stack_value(State, std::int64_t index) = 0;
    virtual bool original_call_failed(
        State,
        std::int64_t nargs,
        std::int64_t nresults,
        bool catch_panics) = 0;
    virtual bool to_boolean(State, std::int64_t index) = 0;
    virtual void set_stack_top(State, std::int64_t count) = 0;
    virtual Error parse_pattern(const ByteString&, Pattern&) = 0; // zDvRmglUn7Os
    virtual Error resolve_process_ids(
        const ByteString&,
        std::vector<std::int32_t>&) = 0; // lfLY9wMdVN
    virtual Error find_pattern_in_process(
        std::int32_t pid,
        const Pattern&,
        std::int64_t& result) = 0; // v_yr0OhQ3HiG
};

// @0x1f1e700: input JSON string; output decoded value or (nil,error).
std::int64_t json_decode_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    const auto error = runtime.decode_json_and_push_result(
        state, runtime.to_string(state, 1));
    if (error) {
        runtime.push_nil(state);
        runtime.push_string(state, *error);
        return 2;
    }
    return 1;
}

// @0x1f1e7c0: input any Lua value; output JSON text or (nil,error).
std::int64_t json_encode_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    const auto value = runtime.lua_value_as_go_value(state, 1);
    ByteString encoded;
    const auto error = runtime.marshal_json(value, encoded);
    if (error) {
        runtime.push_nil(state);
        runtime.push_string(state, *error);
        return 2;
    }
    runtime.push_string(state, encoded);
    return 1;
}

// @0x1f15fe0
std::int64_t print_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state,
    std::uint64_t report_descriptor) {
    const auto count = runtime.argument_count(state);
    ByteString line;
    for (std::int64_t index = 1; index <= count; ++index) {
        if (index > 1) line += static_cast<char>(9);
        line += runtime.to_string(state, index);
    }
    // Recovered: call the report callback even for an empty joined line.
    runtime.report_callback(report_descriptor, line);
    return 0;
}

// @0x1f15b80
std::int64_t object_print_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state,
    std::uint64_t report_descriptor) {
    const auto count = runtime.argument_count(state);
    ByteString line;
    for (std::int64_t index = 1; index <= count; ++index) {
        if (index > 1) line += static_cast<char>(9);
        line += runtime.original_object_to_string(state, index);
    }
    if (!line.empty()) {
        runtime.log_original_object_print(line);
        runtime.report_callback(report_descriptor, line);
    }
    return 0;
}

// @0x1f1ee80: output at most ten initial bytes as integer values.
std::int64_t first_bytes_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    std::vector<std::uint8_t> bytes;
    const auto error = runtime.read_initial_bytes(
        runtime.file_path_argument(state, 1), 10, bytes);
    if (error) return runtime.push_error_pair(state, error);
    return runtime.push_go_value(state, runtime.integer_bytes_as_go_slice(bytes));
}

// @0x1f20300: test only the first two MZ bytes; no PE-header validation.
std::int64_t is_pe_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    std::vector<std::uint8_t> bytes;
    const auto error = runtime.read_initial_bytes(
        runtime.file_path_argument(state, 1), 2, bytes);
    if (error) return runtime.push_error_pair(state, error);

    runtime.push_boolean(
        state, bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z');
    runtime.push_nil(state);
    return 2;
}

// @0x1f1ef80
std::int64_t drives_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    BasicCallbackContracts::Value value;
    const auto error = runtime.list_drives(value);
    return error ? runtime.push_error_pair(state, error) :
        runtime.push_go_value(state, value);
}

// @0x1f1f020
std::int64_t journal_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    auto drive = runtime.trim_space(runtime.to_string(state, 1));
    if (drive.empty()) drive = "C:";

    BasicCallbackContracts::Value value;
    const auto error = runtime.read_journal_records(drive, value);
    return error ? runtime.push_error_pair(state, error) :
        runtime.push_go_value(state, value);
}

// @0x1f1f0e0
std::int64_t time_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    return runtime.push_go_value(state, runtime.current_time_record());
}

// @0x1f203c0
std::int64_t pe_file_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    ByteString value;
    const auto error = runtime.inspect_pe_file(
        runtime.file_path_argument(state, 1), value);
    if (error) return runtime.push_error_pair(state, error);

    runtime.push_string(state, value);
    runtime.push_nil(state);
    return 2;
}

// @0x1f20480: `get` is a named-collection lookup, not an HTTP callback.
std::int64_t get_collection_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    const auto key = runtime.lower_string(
        runtime.trim_space(runtime.to_string(state, 1)));
    BasicCallbackContracts::Value value;
    const auto error = runtime.lookup_named_collection(key, value);
    return error ? runtime.push_error_pair(state, error) :
        runtime.push_go_value(state, value);
}

// @0x1f150e0
std::int64_t flag_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state,
    std::set<ByteString>& seen) {
    const auto message = runtime.flag_message(state);
    if (message.empty()) {
        runtime.push_nil(state);
        return 2; // Recovered oddity: two results after one PushNil.
    }
    if (seen.find(message) != seen.end()) return 0;

    seen.insert(message);
    runtime.log_flag(message + runtime.flag_log_suffix());
    return 0;
}

// @0x1ef3280
std::int64_t find_string_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    const auto argument_count = runtime.argument_count(state);
    if (argument_count < 2) {
        runtime.push_boolean(state, false);
        return 1;
    }

    runtime.get_global(state, "string");
    runtime.get_field(state, -1, "find");
    runtime.remove_stack_value(state, -2);
    if (!runtime.is_function(state, -1)) {
        runtime.pop(state, 1);
        runtime.push_boolean(state, false);
        return 1;
    }

    runtime.insert_stack_value(state, 1);
    if (runtime.original_call_failed(state, argument_count, 1, true)) {
        runtime.set_stack_top(state, 0);
        runtime.push_boolean(state, false);
        return 1;
    }

    const auto found = runtime.to_boolean(state, -1);
    runtime.set_stack_top(state, 0);
    runtime.push_boolean(state, found);
    return 1;
}

// @0x1f36bc0
std::int64_t scan_pattern_callback(
    BasicCallbackContracts& runtime,
    BasicCallbackContracts::State state) {
    BasicCallbackContracts::Pattern pattern;
    if (runtime.parse_pattern(runtime.to_string(state, 1), pattern)) {
        runtime.push_boolean(state, false);
        return 1;
    }

    std::vector<std::int32_t> process_ids;
    const auto selector = runtime.trim_space(runtime.to_string(state, 2));
    if (runtime.resolve_process_ids(selector, process_ids) || process_ids.empty()) {
        runtime.push_boolean(state, false);
        return 1;
    }

    for (const auto process_id : process_ids) {
        std::int64_t found;
        const auto error =
            runtime.find_pattern_in_process(process_id, pattern, found);
        // Recovered: failed process queries are skipped. First positive result wins.
        if (!error && found > 0) {
            runtime.push_boolean(state, true);
            return 1;
        }
    }
    runtime.push_boolean(state, false);
    return 1;
}

// Common failure behavior: JSON/file/drive/journal/PE/collection callbacks expose
// their original `(nil,error)` or Go-value helper conventions. FindString and
// ScanPattern collapse missing functions, parse/lookup failures, and no match to
// one Boolean false. Flag de-duplicates per Lua state through its captured map.
}
