#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: File registry values for Application, Security, and System EventLog channels.
//   Gate: Compares each successful read to its captured unexpanded default using Unicode EqualFold.
//   Output: Emits one EventLogPath report/debug row for each mismatch.
//   Failure: Open/read failures skip a channel; successful handles close in reverse order and close
//            errors are ignored.

namespace ocean::reconstructed::shared_eventlog_path_integrity {

using Handle = std::uint64_t;

template<class T>
struct Read {
    T value{};
    bool error = false;
};

struct Contracts {
    virtual Read<Handle> open_hklm(
        const ByteString&, std::uint32_t access) = 0;
    virtual Read<ByteString> get_string_value(
        Handle, const ByteString&) = 0;
    virtual void close_ignoring_error(Handle) = 0;
    virtual bool go_unicode_equal_fold(
        const ByteString&, const ByteString&) = 0;
    virtual void print_text(const ByteString&) = 0;
    virtual void append_debug_path(
        const ByteString& key,
        const ByteString& expected,
        const ByteString& actual) = 0;
};

struct DeferredKeyClosures {
    Contracts& runtime;
    std::vector<Handle> handles;

    ~DeferredKeyClosures() {
        for (auto handle = handles.rbegin(); handle != handles.rend(); ++handle) {
            runtime.close_ignoring_error(*handle);
        }
    }
};

void check(Contracts& runtime) { // JemWGP_E7G5 @ 0x1296880
    const std::pair<ByteString, ByteString> channels[] = {
        {"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application",
         "%SystemRoot%\\system32\\winevt\\Logs\\Application.evtx"},
        {"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
         "%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"},
        {"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System",
         "%SystemRoot%\\system32\\winevt\\Logs\\System.evtx"},
    };

    // The original registers defers inside the loop. Successful handles remain
    // open until function return, then close in reverse order.
    DeferredKeyClosures deferred_closes{runtime, {}};
    for (const auto& [key, expected] : channels) {
        const auto opened = runtime.open_hklm(key, 1);
        if (opened.error) {
            continue;
        }
        deferred_closes.handles.push_back(opened.value);

        const auto actual = runtime.get_string_value(opened.value, "File");
        if (actual.error ||
            runtime.go_unicode_equal_fold(actual.value, expected)) {
            continue;
        }

        runtime.print_text(
            "Tampered Eventlog:::Boot instance:::The default EventLog path was modified");
        runtime.append_debug_path(key, expected, actual.value);
    }
    // Debug row: ["Detect", "EventLogPath", key, expected, actual]. There is
    // no environment expansion, path normalization, existence/content check,
    // timestamp check, or WARNINGS-slice append.
}

// Five original callback routes confirm the unexpanded %SystemRoot% literal
// comparison. Provider behavior and Unicode EqualFold remain explicit contracts.

}  // namespace ocean::reconstructed::shared_eventlog_path_integrity
