#include "../session/session_types.hpp"
#include <cstdint>
// Recovered behavior summary:
//   Input: NtQuerySystemInformation class 103 into an initialized 8-byte CodeIntegrityInformation
//          buffer.
//   Gate: Tests option bit 2 regardless of native status or returned length.
//   Output: Appends the unsigned test-driver warning when that bit is set.
//   Failure: Procedure lookup failure follows the original panic; a silent native failure normally
//            leaves zero options.

namespace ocean::reconstructed::shared_code_integrity_mode {

using Address = std::uint64_t;

struct CodeIntegrityInformation {
    std::uint32_t length = 8;
    std::uint32_t options = 0;
};

struct Error {
    bool present = false;
};

struct Procedure {
    Address address = 0;
    Error error;
};

struct Contracts {
    virtual Procedure find_procedure(
        const ByteString& library, const ByteString& name) = 0;
    virtual void original_panic(Error) = 0;
    virtual void query_system_information(
        Address function,
        std::uint32_t information_class,
        CodeIntegrityInformation& buffer,
        std::uint32_t bytes,
        std::uint32_t& returned_length) = 0;
    virtual void append_warning(const ByteString&) = 0;
};

bool test_driver_flag(Contracts& runtime) {
    // PEhVuBqkg8Zt.C9TUj_h @ 0x12c5da0
    CodeIntegrityInformation information;
    std::uint32_t returned_length = 0;
    const auto procedure = runtime.find_procedure(
        "ntdll.dll", "NtQuerySystemInformation");
    if (procedure.error.present) {
        runtime.original_panic(procedure.error);
        return false;
    }

    runtime.query_system_information(
        procedure.address, 103, information, 8, returned_length);
    // The original four-argument call ignores NTSTATUS, last error, and
    // returned length. A silent failure normally leaves initialized options at
    // zero; partially written options are still inspected.
    return (information.options & 2) != 0;
}

void check(Contracts& runtime) {
    // vJtYm8.DPFY8kTv.func34 @ 0x179dc80
    if (test_driver_flag(runtime)) {
        runtime.append_warning("Unsigned Test drivers execution is Active");
    }
    // The shared wrapper profiles BYPASS_TestDriversAllowed and defers
    // WaitGroup.Done. It does not change Code Integrity options or load a
    // driver.
}

// Ten query routes, two wrapper routes, and the expected lookup panic confirm
// library/procedure names, class 103, the initial 08 00 00 00 00 00 00 00
// buffer, option bit 1, and ignored status/length behavior.

}  // namespace ocean::reconstructed::shared_code_integrity_mode
