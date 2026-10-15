#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: StorageSpaces-Driver Operational EVTX JSON fields DriveManufacturer, DriveModel, and
//          SystemTime.
//   Gate: A case-sensitive manufacturer substring osfdisk matches without a boot check; a model
//         match additionally requires parsed time strictly after boot.
//   Output: Emits an OSFMount console line and debug row with parsed time, manufacturer, and model.
//   Failure: Open/marshal/unmarshal/time-parse failures skip data; there is no EventID filter,
//            deduplication, or drive enumeration.

namespace ocean::reconstructed::shared_storage_drives {
using Handle=std::uint64_t;
struct Time {
    std::uint64_t wall=0;
    std::int64_t seconds=0;
    std::uint64_t location=0;
};
template<class T>struct Read {
    T value;
    bool error=false;
};
struct Event {
    ByteString drive_manufacturer,drive_model,system_time;
};
struct Contracts{
 virtual Read<Handle> open_evtx(const ByteString&)=0;
 virtual void close_evtx_ignoring_error(Handle)=0;
 virtual Handle events_channel(Handle)=0;
 virtual bool receive_event(Handle,Handle&)=0;
 virtual Read<ByteString> json_marshal_entire_event(Handle)=0;
 virtual Read<Event> json_unmarshal_storage_event(const ByteString&)=0;
 virtual Read<Time> parse_go_time(const ByteString& layout,const ByteString& value)=0;
 virtual bool after(const Time&,const Time&)=0;
 virtual void print_text(const ByteString&)=0;
 virtual void append_debug_time_and_drive(const Time&,const ByteString& manufacturer,const ByteString& model)=0;
};
struct Close{std::function<void()> function;~Close(){function();}};
void check(Contracts& rt,const Time& shared_boot){ //Svd7H_7oO@12647e0
 auto file=rt.open_evtx("C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-StorageSpaces-Driver%4Operational.evtx");
 if(file.error)return;
 Close close{[&]{rt.close_evtx_ignoring_error(file.value);}};
 auto stream=rt.events_channel(file.value);Handle raw=0;
 while(rt.receive_event(stream,raw)){ //func3@1264c40, per-event func3.2@1264ce0
  auto json=rt.json_marshal_entire_event(raw);if(json.error)continue;
  auto event=rt.json_unmarshal_storage_event(json.value);if(event.error)continue;
  const auto& e=event.value;
  auto parsed=rt.parse_go_time("2006-01-02T15:04:05.999999999Z07:00",e.system_time);
  if(parsed.error)continue;
  bool match=e.drive_manufacturer.find("osfdisk")!=ByteString::npos;
  if(!match && e.drive_model.find("osfdisk")!=ByteString::npos)
   match=rt.after(parsed.value,shared_boot);
  if(!match)continue;
  rt.print_text("OSFMount Bypass Method:::Boot instance:::The user mount/dismount a OSFMount Volume.");
  rt.append_debug_time_and_drive(parsed.value,e.drive_manufacturer,e.drive_model);
 }
 //Debug ["Detect","OSFMount",GoTime,manufacturer,model]. No warning global.
 //Matching is case-sensitive. Manufacturer match bypasses the boot-time gate.
 //No EventID filter, deduplication or proof that a mount action occurred.
}
//Typed schema36473c0 is48bytes: Event.EventData.DriveManufacturer at0,
//Event.EventData.DriveModel at16, Event.System.TimeCreated.SystemTime at32.
//The last field is a STRING, parsed only after successful full-event JSON decode.
//Eighteen original instruction routes checked with synthetic EVTX/JSON/time
//providers. Timestamp forwarding was separately verified; no normalization is
//added here. Raw EVTX/BinXML parser is a separate provider. Guest-only source,
//never compiled or executed. Runtime recovery/unwinding is a library contract.
}
