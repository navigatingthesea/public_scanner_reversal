#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: MaxSize values for Security, System, and Application EventLog registry keys.
//   Gate: A successful uint64 read matches only when value is strictly below 0x500000; registry
//         kind is ignored.
//   Output: Emits one MaxSize report and structured detection per matching channel.
//   Failure: Open/read failure suppresses that channel; close failure is ignored and recovery uses
//            fixed crash rows.

namespace ocean::reconstructed::shared_eventlog_maxsize {
struct Open {
    std::uint64_t handle;
    bool error;
};
struct Integer {
    std::uint64_t value;
    std::uint32_t kind;
    bool error;
};
struct Contracts {
    virtual Open open_hklm(const ByteString&,std::uint32_t)=0;
    virtual Integer get_integer(std::uint64_t,const ByteString&)=0;
    virtual void close_key_ignore_error(std::uint64_t)=0;
    virtual void append_original_eventlog_report(const ByteString&)=0;
    virtual void append_structured_detection(const ByteString&,const ByteString&,
                                             const ByteString&,std::uint64_t,const ByteString&)=0;
    virtual void register_original_panic_recovery(const ByteString&,const ByteString&)=0;
};
void check_channel(Contracts& runtime,const ByteString& channel) { //func4@134cbc0
    runtime.register_original_panic_recovery("DEventLogTamper_MaxSize_"+channel,"Failed to check MaxSize for log type");
    const auto path=ByteString("SYSTEM\\CurrentControlSet\\Services\\EventLog\\")+channel;
    const auto key=runtime.open_hklm(path,1);
    if(key.error) return;
    const auto size=runtime.get_integer(key.handle,"MaxSize");
    if(!size.error && size.value<0x500000) {
        runtime.append_original_eventlog_report(
            "EventLog Tamper (MaxSize Reduced):::Boot instance:::The user reduced the "+
            channel+" event log maximum size to force event overwriting");
        runtime.append_structured_detection("Detect","EventLog_MaxSize",channel,size.value,path);
    }
    runtime.close_key_ignore_error(key.handle);
}
void run(Contracts& runtime) { //gnPgc@1294ea0, third of4PDTUOfU children
    runtime.register_original_panic_recovery("DEventLogTamper_MaxSize","Failed to check EventLog max size values");
    for(const auto channel:{"Security","System","Application"}) check_channel(runtime,channel);
}
// Strict unsigned64 <5MiB. Values0/1/0x4fffff report,0x500000/up/0x100000000 do not.
// Registry kind not compared. Query/open errors suppress; closeerror ignored.8
// original full parent fixtures returned, all3 channel order and failure paths.
// No log-file size/contents/event overwrite/timestamp/creator inspection. Label
// asserts intent the presence/value test does not prove. Structured row global572e8e0
// preserves numeric uint64 as a numeric field, not decimal string.
// Recovery rows and the other EventLogDisabler children are in eventlog_recovery.cpp,
// eventlog_minint_check.cpp and eventlog_service_checks.cpp.
// VM-only readable C++ never compiled/run.
}
