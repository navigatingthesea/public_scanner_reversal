#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: A recovered panic interface plus the callback scope and optional channel name.
//   Gate: Emits only when recover returns nonnull.
//   Output: Appends the exact fixed Crash row for the selected EventLog scope.
//   Failure: The recovered value is discarded and this file does not model Go unwinding beyond the
//            contract.

namespace ocean::reconstructed::shared_eventlog_recovery {
enum class Scope {
    Parent,
    MiniNt,
    EventLogService,
    MaxSizeParent,
    MaxSizeChannel,
    Netprofm
};
struct Contracts {
    virtual bool original_recover_interface_nonnull()=0;
    virtual void append_original_crash_log(const std::vector<ByteString>&)=0;
};
void recover(Contracts& runtime,Scope scope,const ByteString& channel={}) {
    if(!runtime.original_recover_interface_nonnull()) return;
    ByteString name,message;
    switch(scope) {
    case Scope::Parent:name="DEventLogTamper";message="Main function execution failed";break;
    case Scope::MiniNt:name="DEventLogTamper_MiniNt";message="Failed to check MiniNt registry key";break;
    case Scope::EventLogService:name="DEventLogTamper_ServiceStart";message="Failed to check EventLog service start type";break;
    case Scope::MaxSizeParent:name="DEventLogTamper_MaxSize";message="Failed to check EventLog max size values";break;
    case Scope::MaxSizeChannel:name="DEventLogTamper_MaxSize_"+channel;message="Failed to check MaxSize for log type";break;
    case Scope::Netprofm:name="DEventLogTamper_Netprofm";message="Failed to check netprofm service start type";break;
    }
    runtime.append_original_crash_log({"Crash",name,message});
}
//12 original closure fixtures returned: nil recover no output; nonnull appends these
// fixed rows, discards recovered value, no rethrow in closure. A recovered child panic
// returns from that child, allowing parent to continue with subsequent children.
// MaxSizeChannel closure captures original channel string, so label is per channel.
// Child service handle defers close before recovery. Logger implementation/output
// transport remains in shared report infrastructure. No native/real panic/C++ execution.
}
