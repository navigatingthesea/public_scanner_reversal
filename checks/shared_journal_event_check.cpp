#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Application.evtx Event ID 3079 records, their JSON VolumeName/SystemTime fields, and the
//          shared boot time.
//   Gate: Requires numeric ID 3079 and JSON SystemTime strictly after boot; ExtraInfo is decoded
//         but never inspected.
//   Output: Emits a Journal Deletion console line and Journal_D debug row containing volume,
//           original time, and elapsed-since-boot text.
//   Failure: File-open, marshal, unmarshal, or time rejection skips a record; this callback has no
//            explicit reader close and reads no USN entries.

namespace ocean::reconstructed::shared_journal_event {
using Handle=std::uint64_t;
struct Time {
    std::uint64_t wall=0;
    std::int64_t seconds=0;
    std::uint64_t location=0;
};
struct Event {
    ByteString extra_info,volume_name;
    Time system_time;
};
template<class T>struct Read {
    T value{};
    bool error=false;
};
struct Contracts{
 virtual Read<Handle> open_evtx(const ByteString&)=0;
 virtual Handle events_channel(Handle)=0;
 virtual bool receive_event(Handle,Handle&)=0;
 virtual std::int64_t event_id(Handle)=0;
 virtual Read<ByteString> json_marshal_entire_event(Handle)=0;
 virtual Read<Event> json_unmarshal_journal_event(const ByteString&)=0;
 virtual bool after(const Time&,const Time&)=0;
 virtual std::int64_t subtract_ns(const Time&,const Time&)=0;
 virtual Time in_local(const Time&)=0;
 virtual ByteString format_time(const Time&,const ByteString&)=0;
 virtual void print_text(const ByteString&)=0;
 virtual void append_debug_volume_time_elapsed(const ByteString&,const Time&,const ByteString&)=0;
};
ByteString elapsed_string(std::int64_t ns){ //sfgHWEzHw@129ef80
 auto units=[&](std::int64_t unit){return static_cast<std::int64_t>(double(ns/unit)+double(ns%unit)/double(unit));};
 const auto hours=units(3600000000000LL),minutes=units(60000000000LL)%60,seconds=units(1000000000LL)%60;
 if(hours>0)return std::to_string(hours)+"h "+std::to_string(minutes)+"m "+std::to_string(seconds)+"s";
 if(minutes>0)return std::to_string(minutes)+"m "+std::to_string(seconds)+"s";
 return std::to_string(seconds)+"s";
 //Truncation and signed remainder preserved; no days unit or negative clamp.
}
void check(Contracts& rt,const Time& shared_boot){ //Iyvu7IhhPRo@129f400
 auto file=rt.open_evtx("C:\\Windows\\System32\\winevt\\Logs\\Application.evtx");if(file.error)return;
 auto stream=rt.events_channel(file.value);Handle raw=0;
 while(rt.receive_event(stream,raw)){
  if(rt.event_id(raw)!=3079)continue;
  auto json=rt.json_marshal_entire_event(raw);if(json.error)continue;
  auto event=rt.json_unmarshal_journal_event(json.value);if(event.error)continue;
  const auto& e=event.value;if(!rt.after(e.system_time,shared_boot))continue;
  const auto elapsed=elapsed_string(rt.subtract_ns(e.system_time,shared_boot));
  const auto formatted=rt.format_time(rt.in_local(e.system_time),"2006-01-02 15:04:05");
  rt.print_text("Journal Deletion:::Boot instance:::USN Journal for "+e.volume_name+" was deleted "+elapsed+" after boot ("+formatted+")");
  rt.append_debug_volume_time_elapsed(e.volume_name,e.system_time,elapsed);
 }
 //Debug ["Detect","Journal_D",VolumeName,ORIGINAL GoTime,elapsedString].
 //No warning-global write, deduplication, Event.Provider/ExtraInfo/content test.
 //No explicit reader.Close in THIS callback; EVTX library ownership is separate.
}
//Typed296byte schema3647440: Event.EventData.ExtraInfo string0, VolumeName16,
//Event.System at32, TimeCreated.SystemTime GoTime at256. Other typed fields
//unmarshaled transiently but not inspected/reported here. Uses raw numeric
//EventID()3079 and JSON timestamp, not Event.TimeCreated(). Subtracts BOOT,
//not NOW. Presentation changes timestamp location only for console date.
//Ten original callback routes and eight original duration formatter routes.
//Underlying EVTX BinXML/record parser remains separate. Guest-only source,
//never compiled or run; original instruction interpretation used synthetic inputs.
}
