#include "../session/session_types.hpp"
#include <memory>
namespace ocean::reconstructed::hook_scan_go_bridge {
// Recovered: call the native hook scanner for a 32-bit PID, parse its borrowed
// JSON string, and project module/hook counts plus the hook list. Null native
// output and JSON failures return wrapped errors; native success/PID are discarded.
struct NativeJson {
    std::int64_t success = 0, pid = 0, modules = 0;
    std::shared_ptr<std::vector<ByteString>> hooks;
};
struct Derived {
    std::int32_t hook_count = 0, module_count = 0;
    ByteString unused_name;
    std::shared_ptr<std::vector<ByteString>> hooks;
};
template <class T> struct Read {
    std::shared_ptr<T> value;
    bool error = false;
    ByteString error_description;
};
struct Contracts {
    virtual std::uint64_t native_scan_process_to_json_cstring(std::uint32_t pid) = 0;
    virtual ByteString go_cstring_to_string(std::uint64_t pointer) = 0; // NULL => empty
    virtual Read<NativeJson> go_json_unmarshal_scan_record(const ByteString &) = 0;
};
Read<NativeJson> decode_native_scan(Contracts &rt, std::int32_t pid) { // TEMjSD@1206400
    const auto native = rt.native_scan_process_to_json_cstring(static_cast<std::uint32_t>(pid));
    const auto json = rt.go_cstring_to_string(native);
    auto parsed = rt.go_json_unmarshal_scan_record(json);
    if (parsed.error)
        return {nullptr, true, "error parsing JSON: " + parsed.error_description};
    return parsed; // success==0 is NOT converted to a Go error
}
Read<Derived> scan(Contracts &rt, std::int32_t pid) { // Tl6EY70aNDCJ@1206960
    if (pid == 0)
        return {nullptr, true, "PID inválido"}; // negative nonzero still reaches native
    auto raw = decode_native_scan(rt, pid);
    if (raw.error)
        return {nullptr, true, raw.error_description};
    auto out = std::make_shared<Derived>();
    out->hook_count = static_cast<std::int32_t>(raw.value->hooks ? raw.value->hooks->size() : 0);
    out->module_count = static_cast<std::int32_t>(raw.value->modules);
    out->hooks = raw.value->hooks; // slice shared, not re-sorted or deduplicated
    return {out, false, {}};
    // Native success/pid discarded. Derived unused_name is an empty Go string.
}
// ABI0 vHNie89ZiTX1@1206340 passes PID DWORD atSP+8 and returns CString atSP+16;
// captured cgo wrapper230ff00 calls native ScanProcessToJson@33cca60.
// Native body uses a thread-local C++ string for JSON output; Go bridge does not
// free that borrowed CString. JSON record48bytes: success0,pid8,modules16,hooks24.
// Exact Go JSON timestamp/number/error/unknown-field behavior remains a standard
// library contract. Seven original bridge routes prove success0 passthrough,
// NULL/JSON error wrapping, empty/duplicate hooks and PID low32 truncation.
// No native/sample/source execution. Native collector body reviewed separately.
} // namespace ocean::reconstructed::hook_scan_go_bridge
