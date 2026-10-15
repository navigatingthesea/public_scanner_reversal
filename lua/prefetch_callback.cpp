#include "query_records.hpp"

namespace ocean::reconstructed::lua_review {
struct PrefetchRecord { // Go type 0x377f160, 144 bytes
    ByteString file_name;
    ByteString executable_name;
    ByteString command_line;
    std::uint32_t file_size = 0;
    ByteString hash;
    ByteString version;
    std::vector<GoTimeWords> last_run_times;
    std::vector<ByteString> files_accessed;
    std::uint32_t run_count = 0;
};

struct PrefetchCallbackContracts {
    using State = std::uint64_t;
    virtual ~PrefetchCallbackContracts() = default;
    virtual ByteString path_argument(State, std::int64_t) = 0;
    virtual QueryError parse_prefetch(
        const ByteString&, PrefetchRecord&) = 0; // GPxy7u3aVEO.DCZmQW01a6t6
    virtual QueryError marshal_prefetch_json(const PrefetchRecord&, ByteString&) = 0;
    virtual void push_nil(State) = 0;
    virtual void push_string(State, const ByteString&) = 0;
    virtual ByteString original_prefetch_error(
        const QueryError&, bool json_stage) = 0;
};

// @0x1f22620
std::int64_t parse_prefetch_callback(
    PrefetchCallbackContracts& runtime,
    PrefetchCallbackContracts::State state) {
    PrefetchRecord record;
    auto error = runtime.parse_prefetch(runtime.path_argument(state, 1), record);
    if (error) {
        runtime.push_nil(state);
        runtime.push_string(state, runtime.original_prefetch_error(error, false));
        return 2;
    }

    ByteString encoded;
    error = runtime.marshal_prefetch_json(record, encoded);
    if (error) {
        runtime.push_nil(state);
        runtime.push_string(state, runtime.original_prefetch_error(error, true));
        return 2;
    }

    runtime.push_string(state, encoded);
    runtime.push_nil(state);
    return 2;
}

// Input is a normalized file path. Output is `(JSON,nil)`, not a Lua table.
// Parse and JSON failures both return `(nil,error)` with distinct formatting stages.
}
