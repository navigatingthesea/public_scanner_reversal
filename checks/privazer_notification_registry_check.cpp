#include "../session/session_types.hpp"

// Recovered behavior summary:
//   Input: Every value data item under the Windows Notifications Data registry key.
//   Gate: Lowercase string or raw binary bytes must contain privazer.exe; binary is tried only
//         after string-read failure.
//   Output: Emits one warning carrying the number of matching registry values.
//   Failure: Open/name-enumeration failure aborts; per-value read failures skip that value and
//            close failure is ignored.

namespace ocean::reconstructed::privazer_notification_registry_review {
using Word = std::uint64_t;
struct Error { Word type = 0, data = 0; bool present() const { return type != 0; } };
struct OpenKey {
    Word handle = 0;
    Error error;
};
struct Names {
    std::vector<ByteString> value;
    Error error;
};
struct TextValue {
    ByteString value;
    std::uint32_t registry_kind = 0;
    Error error;
};
struct BinaryValue {
    std::vector<std::uint8_t> bytes;
    std::uint32_t registry_kind = 0;
    Error error;
};
struct Contracts {
    virtual OpenKey original_open_registry(Word root, const ByteString&, std::uint32_t access) = 0;
    virtual Names original_read_value_names(Word key, GoInt maximum) = 0;
    virtual TextValue original_get_string_value(Word key, const ByteString& name) = 0;
    virtual BinaryValue original_get_binary_value(Word key, const ByteString& name) = 0;
    virtual Error original_close_registry(Word key) = 0;
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
    virtual ByteString original_format_decimal(GoInt) = 0;
    virtual void append_warning(const ByteString&) = 0; //572e7a0 -> WARNINGS
    virtual void original_callback_timing_and_recovery_contract() = 0;
};

bool contains_target(Contracts& runtime, const ByteString& value) {
    return runtime.original_unicode_lowercase(value).find("privazer.exe") != ByteString::npos;
}

// BRZj0zWRfVkD @ 12ab880. Registry VALUE DATA is matched, not value names.
// No timestamp/age/execution verification despite the warning's wording.
void check_notification_values(Contracts& runtime) {
    const auto opened = runtime.original_open_registry(0x80000002,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data", 0x20019);
    if (opened.error.present()) {
        runtime.original_callback_timing_and_recovery_contract();
        return;
    }
    const auto names = runtime.original_read_value_names(opened.handle, 0);
    if (names.error.present()) {
        runtime.original_close_registry(opened.handle);
        runtime.original_callback_timing_and_recovery_contract();
        return;
    }
    GoInt count = 0;
    for (const auto& name : names.value) {
        const auto text = runtime.original_get_string_value(opened.handle, name);
        if (!text.error.present()) {
            if (contains_target(runtime, text.value)) ++count;
            continue; // successful nonmatch does not try binary
        }
        const auto binary = runtime.original_get_binary_value(opened.handle, name);
        if (binary.error.present()) continue;
        ByteString raw;
        for (const auto byte : binary.bytes) raw += static_cast<char>(byte);
        // Raw bytes to Go string, not a UTF16LE decoder or structured parser.
        if (contains_target(runtime, raw)) ++count;
    }
    if (count > 0)
        runtime.append_warning("Privazer recently executed (" +
                               runtime.original_format_decimal(count) + ")");
    runtime.original_close_registry(opened.handle); // ignored error
    runtime.original_callback_timing_and_recovery_contract();
}
// Each matching value adds ONE regardless repeated target occurrences. Returned
// registry kinds are not tested in this body. Multiple names/data duplicates
// count separately. Match accepts prefix/suffix/path/.bak around privazer.exe;
// privazer/privazer64.exe/privazer-space.exe are not that substring.
//32 original fixture paths returned with synthetic registry/string/binary/fmt
// and nil-recover providers. Unicode casing, actual registry errors/data source
// semantics, panic/Go defer/timing are explicit contracts. No native/file/source
// sample or C++ execution/compilation. Notification data proves a match only.
}
