#include "captured_lua_environment.hpp"
#include <functional>
#include <optional>

namespace ocean::reconstructed::lua_review {
using RuleBytes = std::vector<std::uint8_t>;
using LuaError = std::optional<ByteString>;

LuaError validate_rule_payload_for_review(const RuleBytes&);

struct LuaContracts {
    using State = std::uint64_t;
    virtual ~LuaContracts() = default;
    virtual State new_lua_state() = 0; // yU6_LG7y656.EWiw_0uGO@0x10ef140
    virtual void close_lua_state(State) = 0;
    virtual void with_close_deferred(State, std::function<void()>) = 0;
    virtual void open_base(State) = 0;
    virtual void open_table(State) = 0;
    virtual void open_string(State) = 0;
    virtual void open_math(State) = 0;
    virtual void open_coroutine(State) = 0;
    virtual LuaError install_bootstrap_script(
        State,
        const ByteString& script,
        const ByteString& name) = 0;
    virtual void set_global_nil(State, const ByteString&) = 0;
    virtual void install_original_bindings_in_order(
        State,
        std::uint64_t report_callback_descriptor) = 0;
    virtual void set_rule_name_global(State, const ByteString&) = 0; // @0x1f0caa0
    virtual std::int64_t load_rule(
        State,
        const RuleBytes&,
        const ByteString& chunk_name) = 0;
    virtual LuaError wrap_runtime_error(const LuaError&) = 0;
    virtual LuaError protected_call(
        State,
        std::int64_t nargs,
        std::int64_t nresults,
        bool catch_panics) = 0;
    virtual LuaError format_load_error(
        State,
        std::int64_t status,
        const RuleBytes&) = 0;
};

// fn0X6O8_@0x1f0a740, bootstrap @0x1f0a920
LuaError prepare_rule_state(LuaContracts& runtime, LuaContracts::State state) {
    runtime.open_base(state);
    runtime.open_table(state);
    runtime.open_string(state);
    runtime.open_math(state);
    runtime.open_coroutine(state);

    const auto error = runtime.install_bootstrap_script(
        state, bootstrap_script, "=seal");
    if (error) return error;

    for (const auto* name : disabled_globals)
        runtime.set_global_nil(state, name);
    return std::nullopt;
}

// a2OVVxRx@0x1f0bd20
LuaError load_and_call_rule(
    LuaContracts& runtime,
    LuaContracts::State state,
    const RuleBytes& payload,
    const ByteString& rule_name) {
    const auto validation_error = validate_rule_payload_for_review(payload);
    if (validation_error) return validation_error;

    runtime.set_rule_name_global(state, rule_name);
    const auto chunk_name = ByteString(1, static_cast<char>(61)) + rule_name;
    const auto load_status = runtime.load_rule(state, payload, chunk_name);
    if (load_status != 0)
        return runtime.format_load_error(state, load_status, payload);

    const auto call_error = runtime.protected_call(state, 0, 0, true);
    return call_error ? runtime.wrap_runtime_error(call_error) : std::nullopt;
}

// heczHe@0x1f0a560
LuaError process_rule_in_new_state(
    LuaContracts& runtime,
    const RuleBytes& payload,
    const ByteString& rule_name,
    std::uint64_t report_callback) {
    const auto state = runtime.new_lua_state();
    LuaError result;
    runtime.with_close_deferred(state, [&] {
        result = prepare_rule_state(runtime, state);
        if (result) return;

        runtime.install_original_bindings_in_order(state, report_callback);
        result = load_and_call_rule(runtime, state, payload, rule_name);
    });
    return result;
}

// Input: raw Lua rule bytes, rule name, and report callback descriptor. A fresh
// state opens only base/table/string/math/coroutine, installs the boolean string
// bootstrap, nils eight globals, registers captured bindings, validates and loads
// the rule as chunk `=<rule_name>`, then protected-calls it with no arguments or
// results. Preparation, validation, load, and runtime errors return immediately.
// The deferred action closes Lua state; it is not context cancellation.
}
