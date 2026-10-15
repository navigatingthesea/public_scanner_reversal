#include "query_records.hpp"

namespace ocean::reconstructed::lua_review {
struct MemoryReadCallbackContracts {
    using State = std::uint64_t;
    using Handle = std::uint64_t;
    using Value = std::uint64_t;

    virtual ~MemoryReadCallbackContracts() = default;
    virtual std::int64_t to_integer(State, std::int64_t) = 0;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual void push_nil(State) = 0;
    virtual void push_string(State, const ByteString&) = 0;
    virtual ByteString original_invalid_pid_message() = 0;
    virtual ByteString original_empty_pattern_message() = 0;
    virtual QueryError open_process(
        std::uint32_t access,
        bool inherit,
        std::uint32_t pid,
        Handle&) = 0;
    virtual void close_handle(Handle) = 0;
    virtual ByteString original_open_process_error(const QueryError&) = 0;
    virtual Value original_memory_pattern_query(
        Handle,
        const std::vector<std::uint8_t>&,
        std::int64_t third_argument) = 0; // qJSt1XnP
    virtual QueryError marshal_pattern_query_json(Value, ByteString&) = 0;
};

// @0x1f24060
std::int64_t read_process_memory_callback(
    MemoryReadCallbackContracts& runtime,
    MemoryReadCallbackContracts::State state) {
    const auto process_id =
        static_cast<std::uint32_t>(runtime.to_integer(state, 1));
    const auto input = runtime.to_string(state, 2);
    const std::vector<std::uint8_t> pattern(input.begin(), input.end());
    const auto third_argument = runtime.to_integer(state, 3);

    if (process_id == 0) {
        runtime.push_nil(state);
        runtime.push_string(state, runtime.original_invalid_pid_message());
        return 2;
    }
    if (pattern.empty()) {
        runtime.push_nil(state);
        runtime.push_string(state, runtime.original_empty_pattern_message());
        return 2;
    }

    MemoryReadCallbackContracts::Handle handle = 0;
    const auto error = runtime.open_process(0x410, false, process_id, handle);
    if (error) {
        runtime.push_nil(state);
        runtime.push_string(state, runtime.original_open_process_error(error));
        return 2;
    }
    struct CloseHandle {
        MemoryReadCallbackContracts& runtime;
        MemoryReadCallbackContracts::Handle handle;
        ~CloseHandle() { runtime.close_handle(handle); }
    } close{runtime, handle};

    const auto result = runtime.original_memory_pattern_query(
        handle, pattern, third_argument);
    ByteString encoded;
    const auto json_error = runtime.marshal_pattern_query_json(result, encoded);
    if (json_error) {
        runtime.push_nil(state);
        runtime.push_string(state, *json_error);
        return 2;
    }

    runtime.push_string(state, encoded);
    runtime.push_nil(state);
    return 2;
}

// Input is PID, raw string bytes as a pattern, and an unchanged integer option.
// The process is opened with access 0x410 and inherit=false, queried, closed, and
// the provider result is JSON encoded. Every validation/open/JSON failure returns
// `(nil,error)`; success returns `(JSON,nil)`.
}
