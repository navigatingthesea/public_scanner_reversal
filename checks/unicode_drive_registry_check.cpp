#include "../session/session_types.hpp"

// Recovered behavior summary:
//   Input: Registry value names under the captured MountedDevices key path.
//   Gate: Any decoded rune >= U+0080 qualifies; ASCII control and DEL do not.
//   Output: Appends one warning per qualifying value name, including duplicates.
//   Failure: Open/enumeration errors suppress output; key close/timing/recovery remain provider
//            contracts.

namespace ocean::reconstructed::unicode_drive_registry_review {
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
struct Rune {
    std::int32_t value = 0;
    std::size_t next_byte = 0;
};
struct Contracts {
    virtual OpenKey original_open_registry(Word root, const ByteString& path,
                                          std::uint32_t access) = 0;
    virtual Names original_read_value_names(Word key, GoInt maximum) = 0;
    virtual Error original_close_registry(Word key) = 0;
    virtual Rune original_decode_utf8(const ByteString&, std::size_t byte_offset) = 0;
    virtual void append_warning(const ByteString&) = 0; //572e7a0 -> WARNINGS
    virtual void original_callback_timing_and_recovery_contract() = 0; //ROnqY1.func1
};

// ROnqY1 @ 12c78a0: registry VALUE NAMES, not value contents or drive files.
// Any rune >=U+0080 qualifies, including Latin accented letters and RuneError.
// ASCII control/DEL pass. This differs from unicode_path_check.cpp's bounds.
bool has_non_ascii_rune(Contracts& runtime, const ByteString& name) {
    for (std::size_t offset = 0; offset < name.size();) {
        const auto rune = runtime.original_decode_utf8(name, offset);
        if (rune.value >= 128) return true;
        offset = rune.next_byte;
    }
    return false;
}

void check_mounted_device_value_names(Contracts& runtime) {
    // Preserve the captured key's TWO adjacent backslashes. Do not silently
    // canonicalize it to a single separator or claim the real API accepts it.
    const auto opened = runtime.original_open_registry(0x80000002, "SYSTEM\\\\MountedDevices", 0x20019);
    if (opened.error.present()) {
        runtime.original_callback_timing_and_recovery_contract();
        return;
    }
    const auto names = runtime.original_read_value_names(opened.handle, 0);
    if (!names.error.present())
        for (const auto& name : names.value)
            if (has_non_ascii_rune(runtime, name))
                runtime.append_warning(name + " Drive contains a unicode character");
    runtime.original_close_registry(opened.handle); // error ignored
    runtime.original_callback_timing_and_recovery_contract();
}
// Original Go defer handles key-close and timing/recovery during unwinding.
// Explicit normal calls above do not implement Go panic or compile C++ runtime
// bindings. Fixture gorecover provider returned nil for the no-panic paths.
// Nine original fixture paths returned:ASCII/control/DEL, non-ASCII, Unicode,
// duplicates and open/read/close errors. Duplicates append separate warnings;
// final shared WARNINGS normalization may dedup later. No debug rows here.
// No actual registry/volume/file/process/native/sample/C++ execution.
}
