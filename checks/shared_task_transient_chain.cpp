#include "../session/session_types.hpp"
#include <functional>
#include <optional>
#include <unordered_set>
#include <unordered_map>
// Recovered behavior summary:
//   Input: PSReadLine history plus Security.evtx Event ID 4688 CommandLine values.
//   Gate: Requires schtasks and either /create+/run+/delete or doskey+listsize+/create substrings
//         after normalization.
//   Output: Emits at most eight deduplicated SchtasksTransient report/debug rows across both
//           sources.
//   Failure: Provider/decode failures skip evidence; event scanning drains after its 4000
//            eligible-marshal cap.

namespace ocean::reconstructed::shared_task_transient_chain {
using Handle=std::uintptr_t;
struct GoTime {std::uint64_t wall;std::int64_t ext;std::uintptr_t location;bool zero()const{return wall==0&&ext==0;}};
struct JsonValue {
    enum Kind{Other,String,Map}kind=Other;
    ByteString text;
    std::unordered_map<ByteString,JsonValue> fields;
};
struct Contracts {
 virtual ByteString lower_unicode(const ByteString&)=0;
 virtual ByteString trim_unicode_space(const ByteString&)=0;
 virtual ByteString replace_all(const ByteString&,const ByteString& old,const ByteString& replacement)=0;
 virtual ByteString getenv(const ByteString&)=0;
 virtual ByteString windows_filepath_join(const std::vector<ByteString>&)=0;
 virtual std::optional<ByteString> read_entire_file(const ByteString&)=0;
 virtual Handle open_evtx_or_zero(const ByteString&)=0;
 virtual void with_deferred_close(Handle,const std::function<void()>&)=0;
 virtual bool next_event(Handle,Handle& event)=0;
 virtual bool raw_event_before(Handle event,GoTime)=0;
 virtual std::int64_t raw_event_id(Handle event)=0;
 virtual std::optional<ByteString> marshal_event_json(Handle)=0;
 virtual std::optional<JsonValue> unmarshal_json_map_string_interface(const ByteString&)=0;
 virtual void console_report(const ByteString&)=0;
 virtual void append_debug(const std::vector<ByteString>&)=0;
};
bool matches(Contracts& rt,const ByteString& original){ //xCBz_Kb2p3a@12b79a0
 if(original.empty())return false;
 const auto text=rt.trim_unicode_space(rt.replace_all(rt.lower_unicode(original),"\"\"",""));
 const auto has=[&](const ByteString& term){return text.find(term)!=ByteString::npos;};
 if(!has("schtasks"))return false;
 if(has("/create") && has("/run") && has("/delete"))return true;
 if(has("doskey") && has("listsize") && has("/create"))return true;
 return false;
 //Original returns(original string,true) on match, never the normalized copy.
 //Substring presence only: no token, argument-order, process, successful task
 //creation/deletion, executable identity, or actual command-execution validation.
}
void scan_history(Contracts& rt,const std::function<void(const ByteString&)>& callback){ //gWAm0kx@12b5d80
 const auto profile=rt.getenv("USERPROFILE");if(profile.empty())return;
 const auto path=rt.windows_filepath_join({
  profile,"AppData","Roaming","Microsoft","Windows","PowerShell",
  "PSReadLine","ConsoleHost_history.txt"});
 const auto history=rt.read_entire_file(path);if(!history || history->empty())return;
 std::size_t start=0;
 for(;;){
  const auto end=history->find('\n',start);
  const auto line=rt.trim_unicode_space(history->substr(start,end==ByteString::npos?end:end-start));
  if(!line.empty() && matches(rt,line))callback(line);
  if(end==ByteString::npos)break;start=end+1;
 }
 //Whole raw file bytes converted to Go string, split LF, TrimSpace each line.
 //No BOM/UTF16 decoding, file-age gate, line-count bound or other profiles.
}
static const JsonValue* map_field(const JsonValue& value,const ByteString& key){
 if(value.kind!=JsonValue::Map)return nullptr;
 const auto found=value.fields.find(key);
 return found==value.fields.end()?nullptr:&found->second;
}
void scan_security_events(Contracts& rt,GoTime boot,const std::function<void(const ByteString&)>& callback){ //dOxq0D@12b6d20
 const auto file=rt.open_evtx_or_zero(R"(C:\Windows\System32\winevt\Logs\Security.evtx)");if(!file)return;
 rt.with_deferred_close(file,[&]{
  std::int64_t eligible=0;Handle event;
  while(rt.next_event(file,event)){
   if(eligible>=4000)continue; //DRAIN remaining channel, not break
   if(!boot.zero() && rt.raw_event_before(event,boot))continue;
   if(rt.raw_event_id(event)!=4688)continue;
   ++eligible; //before marshal; errors still consume one of4000 slots
   const auto json=rt.marshal_event_json(event);if(!json)continue;
   const auto root=rt.unmarshal_json_map_string_interface(*json);if(!root)continue;
   const auto e=map_field(*root,"Event");if(!e)continue;
   const auto data=map_field(*e,"EventData");if(!data)continue;
   const auto command=map_field(*data,"CommandLine");
   if(!command || command->kind!=JsonValue::String || command->text.empty())continue;
   if(rt.lower_unicode(command->text).find("schtasks")==ByteString::npos)continue;
   if(matches(rt,command->text))callback(command->text);
  }
 });
 //Raw event time used, not JSON SystemTime. Equal boot time passes; zero boot
 //disables Before test. Map and string dynamic types must match at each level.
 //Close runs after drain and during Go unwind. No provider/username/parent gate.
}
void check(Contracts& rt,GoTime boot){ //BdZUamO@12b4180
 std::size_t emitted=0;std::unordered_set<ByteString> seen;
 const auto emit=[&](const ByteString& origin,const ByteString& snippet){ //func2@12b54a0
  if(emitted>7)return;
  const auto key=(origin+"|"+snippet).substr(0,512); //bytes; potential prefix collision
  if(!seen.insert(key).second)return;
  ++emitted;
  rt.console_report("Transient schtasks chain (bypass):::Boot instance:::Scheduled task create/run/delete evasion");
  rt.append_debug({"Detect","SchtasksTransient",origin,snippet});
 };
 const auto receive=[&](const ByteString& origin,const ByteString& command){
  if(!matches(rt,command))return; //callbacks recheck helper, after provider check
  auto snippet=rt.trim_unicode_space(command);
  if(snippet.size()>400)snippet=snippet.substr(0,400)+"..."; //bytes, not Unicode code points
  emit(origin,snippet);
 };
 scan_history(rt,[&](const auto& command){receive("PSReadLine history",command);}); //func3@12b4a80
 scan_security_events(rt,boot,[&](const auto& command){receive("Security.evtx 4688",command);}); //func4@12b49a0
 //Local seen set and limit shared by BOTH sequential sources. Same command in
 //different origins emits twice. Identical truncated snippet within one origin
 //collides. At most8 reports; collection continues after cap. No WARN append.
}
//20 original root/helper routes incl2 forced literal-discovery controls;18 actual
//ASCII predicate/output fixtures. Original callback streams use isolated synthetic
//Go argument spill areas.20 provider routes incl4001 eligible marshal errors show
//exactly4000 marshals then drain. Directory/file/JSON/EVTX/time std contracts remain
//explicit. Performance timing/UI logger omitted under user scope. No panic recovery
//shown in root. All source guest-only, never compiled or run.
}
