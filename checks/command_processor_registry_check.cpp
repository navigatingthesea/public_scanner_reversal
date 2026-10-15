#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: HKLM\SOFTWARE\Microsoft\Command Processor, value autorun.
//   Gate: Any successful string read matches, including an empty value and any returned registry
//         kind.
//   Output: Appends the Command Processor warning once.
//   Failure: Open or read failure suppresses the warning; close failure does not retract it.

namespace ocean::reconstructed::command_processor_registry_review {
using Word=std::uint64_t;
struct Error {Word type=0,data=0;bool present() const{return type!=0;}};
struct OpenKey {Word handle=0;Error error;};
struct StringValue {
    ByteString value;
    std::uint32_t kind=0;
    Error error;
};
struct Contracts {
    virtual OpenKey original_open_registry(Word,const ByteString&,std::uint32_t)=0;
    virtual StringValue original_get_string_value(Word,const ByteString&)=0;
    virtual Error original_close_registry(Word)=0;
    virtual bool original_missing_value_error_comparison(Error)=0;
    virtual void append_warning(const ByteString&)=0;
    virtual void original_callback_timing_and_recovery_contract()=0;
};
// Yz45iqrL@125df80. Dispatcher label CommandProcessor. HKLM only.
// Successful read is sufficient, including EMPTY value. Data/kind ignored;
// no command parsing, execution, file read or execution-history check here.
void check_autorun_value_presence(Contracts& runtime) {
    const auto key=runtime.original_open_registry(0x80000002,
        "SOFTWARE\\Microsoft\\Command Processor",0x20019);
    if(key.error.present()) {
        runtime.original_callback_timing_and_recovery_contract();
        return;
    }
    const auto value=runtime.original_get_string_value(key.handle,"autorun");
    if(!value.error.present()) {
        runtime.append_warning("Command Processor command active.");
    } else {
        (void)runtime.original_missing_value_error_comparison(value.error);
    }
    (void)runtime.original_close_registry(key.handle);
    runtime.original_callback_timing_and_recovery_contract();
}
//10 original paths returned under controlled registry/nil-recover providers.
//Success with empty/ordinary/Unicode values or unrelated kind warns. Real getter
//validation remains its own contract. Open/read errors suppress warning; close
//error retains it. Runtime panic/defer/GC/concurrent warning append are contracts.
//No actual command, registry/native/sample/C++ execution or C++ compilation.
}
