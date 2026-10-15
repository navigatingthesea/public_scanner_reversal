#include "../session/session_types.hpp"
#include <functional>
#include <optional>
// Recovered behavior summary:
//   Input: PowerShell Operational and Windows PowerShell EVTX EventData strings, encrypted
//          serialized rules, and shared boot time.
//   Gate: Requires decodable/loadable rules and event time no earlier than one whole second before
//         boot; every EventData string is scanned with no EventID/provider filter.
//   Output: Emits one PS_Exec console/debug row per matched rule identifier, using HostApplication
//           when extractable.
//   Failure: Open/JSON/time failures skip data; a scanner error stops that file, short rule text
//            returns after opening, and a zero decoded material handle follows the recovered panic
//            path.

namespace ocean::reconstructed::shared_powershell_execution {
struct GoTime {
    std::uint64_t wall;
    std::int64_t ext;
    std::uintptr_t location;
};
using Handle=std::uintptr_t;
struct Event {
    std::vector<ByteString> data;
    ByteString system_time;
};
struct ScanResult {
    bool error;
    std::vector<ByteString> matched_rule_identifiers;
};
struct Contracts {
 virtual void recover_go_panic(const std::function<void()>&,const std::vector<ByteString>&)=0;
 virtual Handle open_evtx_or_zero(const ByteString&)=0;
 virtual void defer_close_evtx(Handle)=0; //assert io.Closer, call Close on unwind
 virtual Handle decode_rule_material_or_zero(const ByteString&)=0; //rule_material_decoder.cpp
 virtual void defer_destroy_material(Handle)=0;
 virtual Handle load_serialized_native_rules_or_zero(Handle material)=0;
 //Caller creates bytes.Reader(data,len,cap,index=0,previousRune=-1) from protected
 //material object's slice32/40/48, then ReadRules. This is not source compilation.
 virtual void defer_destroy_rules(Handle)=0;
 virtual Handle new_native_scanner(Handle rules)=0;
 virtual void defer_destroy_scanner(Handle)=0;
 virtual std::optional<ByteString> next_event_marshaled_json(Handle evtx)=0;
 //Event-channel end is separate from marshal failure; marshal failure skips one.
 virtual bool event_channel_next(Handle evtx,Handle& event)=0;
 virtual std::optional<ByteString> marshal_event(Handle event)=0;
 virtual std::optional<Event> unmarshal_event_200(const ByteString&)=0;
 virtual std::optional<GoTime> parse_time(const ByteString& layout,const ByteString& value)=0;
 virtual std::int64_t subtract_time_ns(GoTime,GoTime)=0;
 virtual ScanResult scan_bytes(Handle scanner,const ByteString&)=0;
 virtual ByteString trim_unicode_space(const ByteString&)=0;
 virtual void console_report(const ByteString&)=0;
 virtual void append_debug(const std::vector<ByteString>&)=0;
 virtual void goroutine_add_two()=0;
 virtual void launch_worker_with_done(const std::function<void()>&)=0;
 virtual void wait_for_both_workers()=0;
 virtual void check_scriptblock_logging_registry()=0; //mJQ9ID3J, mapped separate source
 virtual void check_transcription_registry()=0; //sNLm2y5Vyb, mapped separate source
 virtual void nil_dereference_go_panic()=0;
};
std::optional<ByteString> host_application(Contracts& rt,const ByteString& data){ //vrhz4AIA@12a7c40
 const auto at=data.find("HostApplication="); //first case-sensitive occurrence
 if(at==ByteString::npos)return std::nullopt;
 const auto start=at+16;
 const auto line_end=data.find_first_of("\r\n",start);
 return rt.trim_unicode_space(data.substr(start,line_end==ByteString::npos?line_end:line_end-start));
}
void scan_file(Contracts& rt,const ByteString& path,const ByteString& global_rule_string,GoTime boot){
 //Oap2StG4.func4@131f800. All deferred objects unwind in reverse registration order.
 rt.recover_go_panic([&]{
  const auto file=rt.open_evtx_or_zero(path);if(!file)return;
  rt.defer_close_evtx(file);
  if(global_rule_string.size()<11)return; //open happens BEFORE this gate
  const auto material=rt.decode_rule_material_or_zero(global_rule_string);
  rt.defer_destroy_material(material);
  if(!material)rt.nil_dereference_go_panic(); //original dereferences; not silent skip
  const auto rules=rt.load_serialized_native_rules_or_zero(material);if(!rules)return;
  rt.defer_destroy_rules(rules);
  const auto scanner=rt.new_native_scanner(rules);rt.defer_destroy_scanner(scanner);
  Handle raw_event;
  while(rt.event_channel_next(file,raw_event)){
   const auto json=rt.marshal_event(raw_event);if(!json)continue;
   const auto event=rt.unmarshal_event_200(*json);if(!event)continue;
   const auto when=rt.parse_time("2006-01-02T15:04:05.999999999Z07:00",event->system_time);
   if(!when)continue;
   const auto elapsed=rt.subtract_time_ns(*when,boot);
   //Original truncates to whole seconds toward zero, then tests sign.
   //[-999999999ns,0] passes; <=-1second skips. No upper age limit.
   if((elapsed/1000000000)*1000000000<0)continue;
   for(const auto& data:event->data){
    const auto matches=rt.scan_bytes(scanner,data);
    if(matches.error)return; //one scanner error stops the ENTIRE file
    if(matches.matched_rule_identifiers.empty())continue;
    const auto extracted=host_application(rt,data);
    const auto& shown=extracted && !extracted->empty()?*extracted:data;
    for(const auto& rule:matches.matched_rule_identifiers){
     rt.console_report("Powershell Execution ("+rule+"):::Boot instance:::The user ran an improbable powershell code");
     rt.append_debug({"Detect","PS_Exec",rule,shown,data});
    }
   }
  }
 },{"Crash","Powershell.processFile","Event file processing failed"}); //1320780
 //Cleanup order: scanner, native Rules, protected material, EVTX closer, recovery.
 //No EventID, Provider, channel-name, username, hash, command-execution or dedup
 //filter appears here. Only EventData.Data strings are scanned; JSON Binary unused.
 //No warning572e7a0 append. Both workers append shared Debug directly; caller has
 //WaitGroup join, but no append mutex shown in this body.
}
void check(Contracts& rt,const ByteString& global_rule_string,GoTime boot){ //Oap2StG4@12a7e80
 rt.recover_go_panic([&]{
  rt.goroutine_add_two();
  rt.launch_worker_with_done([&]{scan_file(rt,R"(C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx)",global_rule_string,boot);});
  rt.launch_worker_with_done([&]{
   scan_file(
    rt,
    R"(C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx)",
    global_rule_string,boot);
  });
  rt.wait_for_both_workers();
  rt.check_scriptblock_logging_registry();rt.check_transcription_registry();
 },{"Crash","Powershell","Event log analysis failed"});
}
//27 original root/worker/extractor/recovery fixtures; events/JSON/time/rule-library
//providers synthetic, deferred cleanup static-reviewed. Captured global5733630/38
//was EMPTY. Unknown dynamic rule bytes remain input, never invented as signatures.
//Rule material decode is mapped separately with23 additional original routes.
//Native EVTX BinXML and scanner internals remain explicit library contracts.
//Guest-only readable source, never compiled or run.
}
