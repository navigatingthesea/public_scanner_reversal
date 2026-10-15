#include "../session/session_types.hpp"
#include <vector>
#include <array>
#include <functional>
// Recovered behavior summary:
//   Input: Five service-to-DLL expectations, service PIDs, unloaded-module trace rows, and the SCM
//          service list for the CDPUserSvc pattern.
//   Gate: For each eligible PID, lowercases the first :::-delimited trace field and tests substring
//         containment of the expected DLL; regex service names are unanchored.
//   Output: Emits one restarted-service console line and S_Restarted debug row for every matching
//           trace row.
//   Failure: PID zero, regex/SCM/list failures, or absent rows suppress output; this callback reads
//            no service state or restart event.

namespace ocean::reconstructed::shared_service_unload {
using Handle=std::uint64_t;
template<class T>struct Read {
    T value;
    bool error=false;
};
using ServiceDll=std::pair<ByteString,ByteString>;
struct Contracts {
    virtual std::vector<ServiceDll> original_go_map_iteration(const std::vector<ServiceDll>& contents)=0;
    virtual std::uint32_t service_pid(const ByteString&)=0; //service_pid.cpp: UAy9caHUbZ.NN9p33oaT
    virtual std::vector<ByteString> unloaded_module_rows(std::uint32_t pid)=0; //native_unload_trace.cpp + Go wrapper
    virtual ByteString go_to_lower(const ByteString&)=0;
    virtual Read<Handle> compile_go_regexp(const ByteString&,std::uint32_t syntax_flags,bool longest)=0;
    virtual bool regexp_match_string(Handle,const ByteString&)=0;
    virtual Read<Handle> connect_local_service_manager()=0;
    virtual Read<std::vector<ByteString>> list_services(Handle)=0;
    virtual void close_service_manager_ignoring_error(Handle)=0;
    virtual void print_restart_console(const ByteString& title,const ByteString& description)=0;
    virtual void append_debug(const std::vector<ByteString>&)=0;
    virtual void recovery_scope(const ByteString& site,const std::function<void()>&)=0;
};
struct Close {std::function<void()> function;~Close(){function();}};
void inspect_pid_rows(Contracts& rt,const ByteString& report_name,const ByteString& actual_service,const ByteString& expected_dll){
    const auto pid=rt.service_pid(actual_service);if(pid==0)return;
    for(const auto& row:rt.unloaded_module_rows(pid)){
        const auto delimiter=row.find(":::");
        const auto first_field=row.substr(0,delimiter); //strings.Split(...,":::")[0], including empty field
        if(rt.go_to_lower(first_field).find(rt.go_to_lower(expected_dll))==ByteString::npos)continue;
        rt.print_restart_console("Bypass Method ("+report_name+" Restarted)","The user previously stopped "+report_name+" Service");
        rt.append_debug({"Detect","S_Restarted",report_name});
    }
    //Every matching row reports; duplicates kept. Lowercase byte-contains,
    //not basename/extension equality: prefix/expected.dll.bak also matches.
    //Image size, PE timestamp and checksum fields are ignored by this check.
}
void service_check(Contracts& rt,const ByteString& name,const ByteString& expected_dll){ //TiPMEA.func8@12d3660
    rt.recovery_scope("TiPMEA.func8",[&]{
        if(name.find('{')==ByteString::npos){inspect_pid_rows(rt,name,name,expected_dll);return;}
        //Original Replace(name,"[a-zA-Z0-9]{5}","[a-zA-Z0-9]{5}",1)
        //is a no-op with the captured decoder values; no anchors are added.
        const auto regex=rt.compile_go_regexp(name,0xd4,false);if(regex.error)return;
        const auto manager=rt.connect_local_service_manager();if(manager.error)return;
        Close close{[&]{rt.close_service_manager_ignoring_error(manager.value);}};
        const auto services=rt.list_services(manager.value);
        if(!services.error)for(const auto& actual:services.value)
            if(rt.regexp_match_string(regex.value,actual))inspect_pid_rows(rt,name,actual,expected_dll);
        //Reporting retains original PATTERN name, not the concrete matched
        //service. A longer suffix can match this unanchored Go regexp.
    });
}
void check(Contracts& rt){ //TiPMEA@12d1e80, shared RServices
    rt.recovery_scope("TiPMEA",[&]{
        const std::vector<ServiceDll> expected={{"DPS","dps.dll"},{"SysMain","sysmain.dll"},{"PcaSvc","pcasvc.dll"},
            {"EventLog","wevtsvc.dll"},{"CDPUserSvc_[a-zA-Z0-9]{5}","CDPUserSvc.dll"}};
        for(const auto& [service,dll]:rt.original_go_map_iteration(expected))service_check(rt,service,dll);
    });
    //This detects unload-trace names. It does not stop/restart a service or
    //validate a service-state event. Debug rows contain only the service label,
    //not PID, DLL row, unload sequence/time or raw trace bytes. Warning global untouched.
}
//20 original table/callback cases, synthetic SCM/PID/native rows, original
//string decoders and matching control flow. Native reader and provider limits
//are documented separately. Guest-only source, never compiled/executed.
}
