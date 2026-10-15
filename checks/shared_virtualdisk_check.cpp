#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: VHDMP Operational EVTX events and the shared boot time.
//   Gate: Event ID decimal text must contain 12, timestamp must be after boot, and VHD path must
//         avoid four recovered substring exclusions.
//   Output: Emits a VirtualDisk report/debug row with VHD file, virtual disk, and event time.
//   Failure: Open/marshal/unmarshal failures skip data; matching is not exact event-ID equality and
//            duplicates are preserved.

namespace ocean::reconstructed::shared_virtual_disk {
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
    ByteString vhd_file,virtual_disk;
};
struct Contracts{
 virtual Read<Handle> open_evtx(const ByteString&)=0;
 virtual void close_evtx_ignoring_error(Handle)=0;
 virtual Handle events_channel(Handle)=0;
 virtual bool receive_event(Handle,Handle&)=0;
 virtual std::int64_t event_id(Handle)=0;
 virtual Time event_time_created(Handle)=0;
 virtual ByteString format_int_base10(std::int64_t)=0;
 virtual Read<ByteString> json_marshal_entire_event(Handle)=0;
 virtual Read<Event> json_unmarshal_virtual_disk_event(const ByteString&)=0;
 virtual bool after(const Time&,const Time&)=0;
 virtual ByteString go_unicode_to_lower(const ByteString&)=0;
 virtual void print_text(const ByteString&)=0;
 virtual void append_debug_file_disk_time(const ByteString& file,const ByteString& disk,const Time&)=0;
};
struct Close{std::function<void()> function;~Close(){function();}};
void check(Contracts& rt,const Time& shared_boot){ //F30AdMWzt4Bt@12ca220
 auto file=rt.open_evtx("C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-VHDMP-Operational.evtx");
 if(file.error)return;Close close{[&]{rt.close_evtx_ignoring_error(file.value);}};
 auto stream=rt.events_channel(file.value);Handle raw=0;
 while(rt.receive_event(stream,raw)){
  if(rt.format_int_base10(rt.event_id(raw)).find("12")==ByteString::npos)continue;
  auto json=rt.json_marshal_entire_event(raw);if(json.error)continue;
  auto decoded=rt.json_unmarshal_virtual_disk_event(json.value);if(decoded.error)continue;
  if(!rt.after(rt.event_time_created(raw),shared_boot))continue;
  const auto& event=decoded.value;
  if(rt.go_unicode_to_lower(event.vhd_file).find("sandboxes")!=ByteString::npos)continue;
  if(event.vhd_file.find("Containers")!=ByteString::npos)continue;
  if(event.vhd_file.find("C:\\Program Files\\WSL")!=ByteString::npos)continue;
  if(event.vhd_file.find("Virtual Machines")!=ByteString::npos)continue;
  rt.print_text("Bypass Method (VirtualDisk):::Boot instance:::The user made a VirtualDisk since boot instance.");
  const auto reported_time=rt.event_time_created(raw); //a second method call
  rt.append_debug_file_disk_time(event.vhd_file,event.virtual_disk,reported_time);
 }
 //Debug ["Detect","VirtualDisk",VhdFile,VirtualDisk,GoTime]. No warning global.
 //All four exclusions are substring tests; only sandboxes is case-insensitive.
 //No VHD extension/path normalization, equality-to-ID12 test or deduplication.
}
//Captured typed JSON schema3772760 has776bytes and many unused fields. Used
//fields Event.EventData.VhdFile and Event.EventData.VirtualDisk are at456/488.
//Root Path, VhdType, VirtualDisk, VmId, WriteDepth and System are NOT substituted
//for nested Event.EventData fields. Full typed JSON decoding still occurs and
//can fail on malformed unused fields. Timestamp used here comes from the raw
//Event.TimeCreated method, not the nested JSON SystemTime string.
//Twenty-three original instruction routes:14 control/forced exclusion routes
//and9 actual ASCII path/literal-match comparisons. Original string decoders
//interpreted; EVTX/JSON/Time methods synthetic. Runtime recovery and Unicode
//case conversion are explicit standard contracts. Raw parser remains separate.
//Guest-only review source; never compiled or executed.
}
