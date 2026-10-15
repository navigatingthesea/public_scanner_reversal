#include "query_records.hpp"

namespace ocean::reconstructed::lua_review {
struct ResultCallbackContracts {
    using State = std::uint64_t;
    virtual ~ResultCallbackContracts() = default;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual ByteString trim_space(const ByteString&) = 0;
    virtual ByteString lower_string(const ByteString&) = 0;
    virtual ByteString original_rule_origin(State) = 0; // wsaMXkhmwZ@1f0cc40
    virtual void original_log(const ByteString&) = 0; // TYheK4ZApSl3
    virtual void append_original_critical_detection(
        const std::array<ByteString, 4>&) = 0; // globals 0x572e8e0/e8/f0
    virtual void append_original_warning(const ByteString&) = 0; // 0x572e7a0/a8/b0
};

// @0x1f33680
std::int64_t result_callback(
    ResultCallbackContracts& runtime,
    ResultCallbackContracts::State state) {
    const auto message = runtime.trim_space(runtime.to_string(state, 1));
    const auto level = runtime.lower_string(
        runtime.trim_space(runtime.to_string(state, 2)));
    if (message.empty()) return 0;

    auto origin = runtime.original_rule_origin(state);
    if (origin.empty()) origin = "lua";
    runtime.original_log(origin + ":::VOSYYOYYOYVOVOSYYOFOEFOE");

    if (level == "critical") {
        runtime.original_log(
            origin + ":::Lua detection:::A forensic Lua rule matched");
        runtime.append_original_critical_detection(
            {"Detect", "Lua_Result", origin, message});
    } else if (level == "warning") {
        runtime.append_original_warning("[lua:" + origin + "] " + message);
    }
    return 0;
}

// Input is trimmed message and trimmed/lowercased level; empty messages do
// nothing. Every nonempty level emits the opaque origin suffix log. `critical`
// also logs a detection description and appends four strings to detections;
// `warning` appends one formatted warning. Other levels append no result.
}
