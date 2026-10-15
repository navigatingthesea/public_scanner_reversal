#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Presence of HKLM\SYSTEM\CurrentControlSet\Control\MiniNt.
//   Gate: A successful key open is sufficient; no values or timestamps are read.
//   Output: Emits the MiniNt EventLog report and structured detection.
//   Failure: Open failure suppresses output; close failure is ignored.

namespace ocean::reconstructed::shared_eventlog_minint {
struct Open {
    std::uint64_t handle;
    bool error;
};
struct Contracts {
    virtual Open open_hklm(const ByteString&,std::uint32_t)=0;
    virtual void close_key_ignore_error(std::uint64_t)=0;
    virtual void append_original_eventlog_report(const ByteString&)=0;
    virtual void append_structured_detection(const std::vector<ByteString>&)=0;
    virtual void register_original_panic_recovery(const ByteString&,const ByteString&)=0;
};
void check(Contracts& runtime) { //ifNTMek@1294080, first of4 PDTUOfU children
    runtime.register_original_panic_recovery("DEventLogTamper_MiniNt","Failed to check MiniNt registry key");
    const auto key=runtime.open_hklm("SYSTEM\\CurrentControlSet\\Control\\MiniNt",1);
    if(key.error) return;
    runtime.close_key_ignore_error(key.handle);
    runtime.append_original_eventlog_report(
        "EventLog Tamper (MiniNt Key):::Boot instance:::The user created the MiniNt registry key to suppress Security event generation");
    runtime.append_structured_detection({"Detect","EventLog_MiniNt",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt"});
}
// Presence only. No value reads, timestamps, creation-attribution or actual Security
// event-generation test. The prose is the scanner's label, not proof of who created
// this key or when. Open failure suppresses, close error ignored.2 original full
// delegate cases returned. Output interface slice global572e8e0, separate from
// warning strings and the event-log-report logger. The other three delegates are in
// eventlog_service_checks.cpp and eventlog_maxsize_check.cpp.
// VM-only C++ review source, never compiled/run.
}
