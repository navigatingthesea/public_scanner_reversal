#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: EnableSuperfetch under PrefetchParameters.
//   Gate: Requires a successful integer read exactly equal to uint64 1; registry kind is ignored.
//   Output: Appends the Prefetch Run-logs warning.
//   Failure: Open/read failure suppresses output; close failure does not retract it.

namespace ocean::reconstructed::prefetch_setting_warning_review {
using Word = std::uint64_t;
struct Error { Word type = 0, data = 0; bool present() const { return type != 0; } };
struct OpenKey {
    Word handle = 0;
    Error error;
};
struct IntegerValue {
    Word number = 0;
    std::uint32_t kind = 0;
    Error error;
};
struct Contracts {
    virtual OpenKey original_open_registry(Word, const ByteString&, std::uint32_t) = 0;
    virtual IntegerValue original_get_integer_value(Word, const ByteString&) = 0;
    virtual Error original_close_registry(Word) = 0;
    virtual bool original_missing_value_error_comparison(Error) = 0;
    virtual void append_warning(const ByteString&) = 0;
    virtual void original_normal_recovery_contract() = 0;
};
// A7r0EG7c95jA @12a8c80, dispatcher label PrefetchBypass.
// Exact name is EnableSuperfetch. The callback warns only for uint64 value1,
// ignoring returned registry kind. It does not inspect prefetch files/logs here.
void check_superfetch_setting(Contracts& runtime) {
    const auto opened = runtime.original_open_registry(0x80000002,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
        0x20019);
    if (opened.error.present()) {
        runtime.original_normal_recovery_contract();
        return;
    }
    const auto read = runtime.original_get_integer_value(opened.handle, "EnableSuperfetch");
    if (!read.error.present()) {
        if (read.number == 1) runtime.append_warning("Prefetch Run-logs disabled");
    } else {
        (void)runtime.original_missing_value_error_comparison(read.error);
    }
    (void)runtime.original_close_registry(opened.handle);
    runtime.original_normal_recovery_contract();
}
//15 original fixtures returned with intercepted registry and nil-recover
//providers:0/2/3/max values reject;1accepts;0x100000001rejects (64-bit comparison).
//Open/read errors suppress warning; close error retains positive warning.
//Real getter validation, panic/defer/GC/concurrent warning appends are contracts.
//No reconstructed C++ compiled/run; no sample/native/registry API executed.
}
