#include "../session/session_types.hpp"
namespace ocean::reconstructed::native_hook_scan_json {
// Recovered: open one process, enumerate modules, scan their .text sections, and
// serialize success, PID, module count, and hooks into a thread-local JSON string.
// Open failure reports success=0; later read/scan failures may still report success=1.
using Handle = std::uint64_t;
struct Module {
    std::uint64_t base;
    std::uint32_t image_size;
    ByteString path, name;
};
struct ThreadState {
    bool initialized = false;
    ByteString json;
};
struct Contracts {
    virtual void
    initialize_decoder_64bit_and_intel_formatter() = 0; // decoder(0,2), formatter(style1),
                                                        // property(0,1)
    virtual Handle open_process(std::uint32_t access, bool inherit, std::uint32_t pid) = 0;
    virtual void close_process_ignoring_status(Handle) = 0;
    virtual std::vector<Module> enumerate_modules(Handle, std::uint32_t pid) = 0;
    virtual void collect_hook_descriptions(Handle, const std::vector<Module> &,
                                           std::vector<ByteString> &) = 0;
    virtual ByteString original_pid_decimal(std::uint32_t) = 0; // 3409150 / native to_string form
};
ByteString quote_hook(const ByteString &hook) {
    ByteString result = "\"";
    for (unsigned char byte : hook) {
        if (byte == '\\' || byte == '"')
            result += '\\';
        result += char(byte);
    }
    result += '"';
    return result;
    // Only quote/backslash escaped. Control bytes are not JSON-escaped here.
}
const char *scan_process_to_json(Contracts &rt, ThreadState &thread,
                                 std::uint32_t pid) { // ScanProcessToJson@33cca60..33cd0a0
    if (!thread.initialized) {
        thread.json.clear();
        thread.initialized = true;
    } else
        thread.json.clear();
    const auto process = rt.open_process(0x1fffff, false, pid);
    if (process == 0 || process == UINT64_MAX) {
        thread.json = "{\"success\":0,\"pid\":" + rt.original_pid_decimal(pid) +
                      ",\"modules\":0,\"hooks\":[]}";
        return thread.json.c_str();
    }
    rt.initialize_decoder_64bit_and_intel_formatter();
    const auto modules = rt.enumerate_modules(process, pid);
    std::vector<ByteString> hooks;
    rt.collect_hook_descriptions(process, modules, hooks);
    rt.close_process_ignoring_status(process); // explicit, before JSON serialization
    thread.json = "{\"success\":1,\"pid\":" + rt.original_pid_decimal(pid) +
                  ",\"modules\":" + std::to_string(modules.size()) + ",\"hooks\":[";
    bool comma = false;
    for (const auto &hook : hooks) {
        if (comma)
            thread.json += ',';
        comma = true;
        thread.json += quote_hook(hook);
    }
    thread.json += "]}";
    return thread.json.c_str();
    // success1 means process open succeeded; enumeration/read/hook failures can
    // still produce empty results. No numeric hook-count field or raw module list.
}
// Original uses TLS string at TLS-block+0x758, flag+0x770 and registers a thread
// destructor on first use. Returned CString borrowed until next call on same
// thread or thread exit. Allocation capacity/SSO addresses remain stdlib details.
// OpenProcess-like protected thunk79b8e66 resumes at call+6, exposing64bit handle
// move hidden by the fake linear instruction. Original API export endpoint is
// captured, role follows access mask/ABI/dataflow; no API was actually executed.
// Top JSON/control is statically reviewed against full unwind-range draft/ASM,
// with Go JSON bridge7 routes, dispatcher24, enum11, comparator25, names17 and
// decoder8 independently interpreted. Top TLS/stringstream/exception paths not
// claimed dynamically fixture-covered. Exception before explicit CloseProcess
// can leak the handle; ordinary native destructors still follow unwind metadata.
// Guest-only review source. Never compiled, run or exported to host.
} // namespace ocean::reconstructed::native_hook_scan_json
