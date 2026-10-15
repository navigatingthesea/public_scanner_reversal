#include "../session/session_types.hpp"
#include <set>
#include <vector>
// Recovered behavior summary:
//   Input: USB enumeration registry trees, service/class strings, instance timestamps, and a cached
//          boot timestamp.
//   Gate: Applies recovered case-sensitive service classification, time threshold, prefix
//         deduplication, and recursive depth behavior.
//   Output: Emits USB removal/storage/input findings with classification and time evidence.
//   Failure: Registry/stat/native uptime failures follow recovered skip/abort/recovery paths;
//            global classification can remain stale.

namespace ocean::reconstructed::shared_usb_removal_check {
using Handle=std::uint64_t;
struct Time {
    std::uint64_t wall,ext,location;
};
struct Open {Handle handle;bool error;};
struct Names {
    std::vector<ByteString> values;
    bool error;
};
struct Stat {Time modified;bool error;};
struct StringResult {
    ByteString value;
    bool error;
};
struct Boot {
    std::int64_t unix_seconds;
    bool error;
};
struct NativeUptime {
    std::uint64_t milliseconds,last_error;
};
struct Uptime {
    std::uint64_t seconds;
    bool error;
};
struct BootContracts {
    virtual bool find_kernel32_proc(const ByteString&)=0;
    virtual void panic_with_original_resolution_error()=0;
    virtual NativeUptime call_resolved_uptime_without_arguments()=0;
    virtual std::int64_t original_now_unix_seconds()=0;
    virtual std::int64_t atomic_load_boot_cache()=0;
    virtual void atomic_exchange_boot_cache(std::int64_t)=0;
};
Uptime uptime_seconds(BootContracts& runtime) { //FETW@bf7620
    const bool found64=runtime.find_kernel32_proc("GetTickCount64");
    // Original calls Find AGAIN on whichever proc was selected.
    if(!runtime.find_kernel32_proc(found64 ? "GetTickCount64" : "GetTickCount")) {
        runtime.panic_with_original_resolution_error();return {0,true};
    }
    const auto result=runtime.call_resolved_uptime_without_arguments();
    if(result.last_error!=0) return {0,true};
    // Original signed64 multiplication wraps, then float Seconds -> uint64.
    const auto wrapped_ns=std::int64_t(result.milliseconds*std::uint64_t(1000000));
    const double seconds=double(wrapped_ns/1000000000)+double(wrapped_ns%1000000000)/1e9;
    return {std::uint64_t(seconds),false};
}
Boot cached_boot_timestamp(BootContracts& runtime) { //Kjb@bf7740
    const auto cached=runtime.atomic_load_boot_cache();
    if(cached!=0) return {cached,false};
    const auto uptime=uptime_seconds(runtime);
    if(uptime.error) return {0,true};
    const auto value=runtime.original_now_unix_seconds()-std::int64_t(uptime.seconds);
    runtime.atomic_exchange_boot_cache(value);return {value,false};
    // No once lock or compare-exchange; concurrent empty-cache calls may compute
    // different values. Zero result is not a persistent cache hit.
}
struct Contracts {
    virtual Boot original_cached_boot_timestamp()=0; //reviewed cached_boot_timestamp above
    virtual Time original_unix_time(std::int64_t)=0;
    virtual Time original_add_ns(Time,std::int64_t)=0;
    virtual Open open_hklm(const ByteString&,std::uint32_t)=0;
    virtual Names read_all_subkey_names(Handle)=0;
    virtual Stat stat_key(Handle)=0; // FILETIME from registry KeyInfo+20, original conversion
    virtual StringResult get_string(Handle,const ByteString&)=0;
    virtual void register_close_on_function_return(Handle)=0;
    virtual bool original_after(Time,Time)=0;
    virtual std::int64_t original_sub_ns(Time,Time)=0;
    virtual std::int64_t original_since_ns(Time)=0;
    virtual ByteString original_duration_text(std::int64_t)=0; //f23020, days/hours/minutes/seconds
    virtual void append_usb_report(const ByteString&)=0; //global572e820, not warnings572e7a0
    virtual void register_original_panic_recovery(const ByteString&)=0;
    // Classification is global572c8d0 and can persist across keys/recursive calls.
    virtual ByteString current_device_classification()=0;
    virtual void set_device_classification(const ByteString&)=0;
};
std::vector<ByteString> split_path(const ByteString& path) {
    std::vector<ByteString> out;std::size_t begin=0;
    for(;;) {const auto next=path.find('\\',begin);out.push_back(path.substr(begin,next-begin));
        if(next==ByteString::npos) return out;begin=next+1;}
}
bool classify_service(Contracts& runtime,const ByteString& value) {
    // Original GetStringValue error is not tested; only returned bytes are searched.
    if(value.find("USBSTOR")!=ByteString::npos) runtime.set_device_classification("Storage");
    else if(value.find("HidUsb")!=ByteString::npos) runtime.set_device_classification("Input");
    else if(value.find("usbaudio")!=ByteString::npos) return false; //ABORT current scan
    else if(value.find("usbccgp")!=ByteString::npos) runtime.set_device_classification("usbccgp");
    // Nonmatching service leaves prior GLOBAL classification unchanged.
    return true;
}
ByteString duration_text(std::int64_t ns) {
    const double hours=double(ns/3600000000000LL)+double(ns%3600000000000LL)/3600000000000.0;
    const auto days=std::int64_t(hours/24.0);
    if(days>0) return std::to_string(days)+" days ago";
    const auto whole_hours=std::int64_t(hours);
    if(whole_hours>0) return std::to_string(whole_hours)+" hour/s ago";
    const auto minutes=std::int64_t(double(ns/60000000000LL)+double(ns%60000000000LL)/60000000000.0);
    if(minutes>0) return std::to_string(minutes)+" min ago";
    return "<59 sec ago";
}
void scan(Contracts& runtime,const ByteString& root,Time baseline,std::int64_t depth) {
    runtime.register_original_panic_recovery("cpmI3qk");
    const auto opened=runtime.open_hklm(root,0x20119);
    if(opened.error) return;
    runtime.register_close_on_function_return(opened.handle);
    const auto children=runtime.read_all_subkey_names(opened.handle);
    if(children.error) return;
    std::set<ByteString> already_reported; // local to EACH invocation
    for(const auto& child:children.values) {
        const auto full=root+"\\"+child;
        const auto key=runtime.open_hklm(full,0x20119);
        if(key.error) continue;
        runtime.register_close_on_function_return(key.handle);
        const auto metadata=runtime.stat_key(key.handle);
        if(metadata.error) continue;
        const auto instances=runtime.read_all_subkey_names(key.handle);
        if(instances.error) return; // abort entire current scan, not just one child
        for(const auto& instance:instances.values) {
            const auto instance_path=full+"\\"+instance;
            if(split_path(instance_path).size()!=6) continue;
            const auto device=runtime.open_hklm(instance_path,0x20119);
            if(device.error) continue;
            // Original instance handle is not registered for close on this path.
            if(!classify_service(runtime,runtime.get_string(device.handle,"Service").value)) return;
        }
        auto recursive_path=full;
        if(runtime.original_after(metadata.modified,baseline)) {
            const auto delta=runtime.original_sub_ns(metadata.modified,baseline);
            const double seconds=double(delta/1000000000)+double(delta%1000000000)/1e9;
            if(std::int64_t(seconds)>10) {
                const auto at=recursive_path.find("USB\\");
                if(at!=ByteString::npos) recursive_path=recursive_path.substr(at+4);
                if(recursive_path.size()>16 &&
                   !already_reported.count(recursive_path.substr(0,17)) &&
                   runtime.current_device_classification()=="Storage") {
                    const auto elapsed=runtime.original_since_ns(metadata.modified);
                    const auto first=duration_text(elapsed);
                    const auto second=duration_text(elapsed);
                    const auto detail=recursive_path+" unpluged "+second;
                    runtime.append_usb_report("USB Removal:::Boot instance:::"+first+":::"+
                        recursive_path+":::"+runtime.current_device_classification()+":::.:::"+detail);
                    already_reported.insert(recursive_path.substr(0,17));
                }
            }
        }
        // Original reuses the possibly STRIPPED path after the timestamp branch.
        if(depth>0) scan(runtime,recursive_path,baseline,depth-1);
    }
}
void run(Contracts& runtime) { //OobnwSELL_@12c9120
    runtime.register_original_panic_recovery("OobnwSELL_");
    const auto boot=runtime.original_cached_boot_timestamp();
    if(boot.error) return;
    const auto baseline=runtime.original_add_ns(runtime.original_unix_time(boot.unix_seconds),180000000000);
    scan(runtime,"SYSTEM\\ControlSet001\\Enum\\USB",baseline,1);
}
//26 original synthetic registry tests returned. Storage10/10.9s false,11s true;
// case-sensitive substring, same first17 bytes dedup, short names, read/stat/open
// errors, stale global classification and returned string on query error matter.
// Defer registration modeled inertly in probes; close/recovery above is from static
// original wrappers. Boot provider still needs DLL/proc/uptime pointer provenance;
// Duration helper separately verified12 original cases. usbaudio ABORT confirmed;
// Captured LazyProc name/proc/DLL descriptors prove kernel32 GetTickCount64 preferred,
// GetTickCount fallback.5 original synthetic native-result cases returned and both-
// Find-errors reached captured panic; 123456ms ->123seconds,999ms ->0, lastError5=>err.
// Complete recovery/logging body details and extreme float-to-uint64 behavior remain
// explicit review boundaries. This file performs no actual Windows API calls.
// VM-only readable C++, never compiled or run.
}
