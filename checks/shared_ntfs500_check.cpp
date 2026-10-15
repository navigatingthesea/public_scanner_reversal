#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: Microsoft-Windows-Ntfs Operational events and a cutoff computed once as now minus
//          exactly 24 hours.
//   Gate: Requires JSON EventID.Value exactly equal to string 500 and JSON SystemTime strictly
//         after the cutoff.
//   Output: Emits an NTFS tampering console line and NTFS_Event500 debug row with event time and
//           cutoff.
//   Failure: Open, marshal, unmarshal, and time failures skip records; close errors are ignored and
//            no shared boot time is used.

namespace ocean::reconstructed::shared_ntfs500 {
using Handle=std::uint64_t;
struct Time {
    std::uint64_t wall=0;
    std::int64_t seconds=0;
    std::uint64_t location=0;
};
struct Event {
    ByteString id_value;
    Time system_time;
};
template<class T>struct Read {
    T value;
    bool error=false;
};
struct Contracts {
    virtual Time now()=0;
    virtual Time add_ns(const Time&,std::int64_t)=0;
    virtual bool after(const Time&,const Time&)=0;
    virtual Read<Handle> open_evtx(const ByteString&)=0;
    virtual void close_evtx_ignoring_error(Handle)=0;
    virtual Handle events_channel(Handle)=0;
    virtual bool receive_event(Handle channel,Handle& event)=0;
    virtual Read<ByteString> json_marshal_entire_evtx_event(Handle event)=0;
    virtual Read<Event> json_unmarshal_ntfs_event(const ByteString&)=0;
    virtual void print_text(const ByteString&)=0;
    virtual void append_debug_event_cutoff(const Time& event,const Time& cutoff)=0;
};
struct Close {std::function<void()> function;~Close(){function();}};
void check(Contracts& rt){ //AksJRJEgQR@12a1c40, shared J500 callback
    const auto cutoff=rt.add_ns(rt.now(),-86400000000000LL); //once, before file open: exactly24hours ago
    const auto file=rt.open_evtx("C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Ntfs%4Operational.evtx");
    if(file.error)return;
    Close close{[&]{rt.close_evtx_ignoring_error(file.value);}};
    const auto stream=rt.events_channel(file.value);Handle raw=0;
    while(rt.receive_event(stream,raw)){
        const auto json=rt.json_marshal_entire_evtx_event(raw);if(json.error)continue;
        const auto event=rt.json_unmarshal_ntfs_event(json.value);if(event.error)continue;
        if(event.value.id_value!="500")continue; //exact string; not numeric or zero-padded equality
        if(!rt.after(event.value.system_time,cutoff))continue;
        rt.print_text("NTFS Eventlog tampering:::Boot instance");
        rt.append_debug_event_cutoff(event.value.system_time,cutoff);
    }
    //Typed row: ["Detect","NTFS_Event500",GoTime(event),GoTime(cutoff)].
    //No warning-global write, deduplication, early exit or shared boot cutoff.
    //The hardcoded System32 path has no Sysnative/SystemRoot fallback here.
}
//Captured JSON type3647640 is48bytes: Event.System.EventID.Value string at0,
//Event.System.TimeCreated.SystemTime GoTime at16, Event.EventData generic map
//at40. Entire events are marshaled, then decoded into this type before filtering.
//EventData is parsed/retained transiently but not consulted or included in this
//callback's report. JSON timestamp parsing follows Go Time.UnmarshalJSON.
//Ten original routes cover stream/open/JSON failures, exact ID, cutoff and
//duplicate events. EVTX/JSON/time providers synthetic; underlying BinXML/chunk
// parser is mapped by windows_evtx_reader.cpp; generic BinaryXML node decoding remains a library
// boundary. Library goroutine failures are not proven caught
//by this callback. Guest-only source, never compiled or executed.
}
