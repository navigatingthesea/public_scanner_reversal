#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Hook-description rows returned by the native scanner for seven service PIDs, plus a
//          configured exclusion list.
//   Gate: Skips the entire check when OS description contains exact Windows 11; otherwise
//         lowercases each description and suppresses configured substring matches.
//   Output: Emits one Hook console/debug row per remaining description, including duplicates and
//           empty descriptions.
//   Failure: Scanner error or missing result pointer suppresses that service; PID zero is still
//            forwarded and native byte comparison remains a separate provider.

namespace ocean::reconstructed::shared_service_hooks {
struct Scan {
    std::vector<ByteString> hook_descriptions;
    bool error=false,pointer_present=true;
};
struct Contracts{
 virtual std::int64_t service_pid(const ByteString&)=0; //NN9p33oaT; sizing/errors source in service_pid.cpp
 virtual Scan scan_process(std::int32_t pid)=0; //WNXr5n.Tl6EY70aNDCJ -> native .text scan
 virtual ByteString unicode_to_lower(const ByteString&)=0;
 virtual void print_text(const ByteString&)=0;
 virtual void append_debug_hook(const ByteString&)=0;
};
bool ignored(Contracts& rt,const ByteString& description,const std::vector<ByteString>& configured){ //wDTDJaL@12c10c0
 const auto lower=rt.unicode_to_lower(description);
 for(const auto& item:configured)if(lower.find(item)!=ByteString::npos)return true;
 return false; //configured items are NOT lowercased here
}
void inspect_service(Contracts& rt,const ByteString& service,std::int32_t pid,const std::vector<ByteString>& exclusions){ //clGlGI@12c1180
 auto scan=rt.scan_process(pid);if(scan.error || !scan.pointer_present)return;
 for(const auto& description:scan.hook_descriptions){
  if(ignored(rt,description,exclusions))continue;
  rt.print_text("System Hooking:::Boot instance:::A system service was hooked to change its functionality");
  rt.append_debug_hook(service+": "+description);
 }
 //Debug ["Detect","Hook",service+": "+description], including duplicate/empty descriptions.
}
void check(Contracts& rt,const ByteString& global_os_description,const std::vector<ByteString>& exclusions){ //A7Ey7axB@12c1420
 if(global_os_description.find("Windows 11")!=ByteString::npos)return; //exact case, whole checker skipped
 for(const ByteString name:{"SysMain","DPS","PcaSvc","RasMan","BFE","Dnscache","EventLog"})
  inspect_service(rt,name,static_cast<std::int32_t>(rt.service_pid(name)),exclusions);
 //Captured exclusion string slice56632d0 has exactly one item: kernelbase.dll.
 //Captured value is evidence for this snapshot, not a guarantee of future config.
 //No PID>0 gate, warning-global write, boot/time comparison or deduplication.
 //Native response rows are formatted HOOK DESCRIPTIONS, not a module-name list.
}
//Ten original callback/wrapper routes, captured exclusion list and seven bridge
//routes verified using synthetic native results. Native ScanProcessToJson,
//module enumeration/file reader/.text comparator need their separate body
//review; application reporting source alone is not completion of the native scan.
//Guest-only source, never compiled/run.
}
