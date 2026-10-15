#include "../session/session_types.hpp"
#include <vector>
#include <map>
#include <set>
#include <array>
#include <functional>
#include <algorithm>
#include <bit>
// Recovered behavior summary:
//   Input: Process creation times for SysMain, PcaSvc, EventLog, DPS, DusmSvc, and CryptSvc plus
//          cached service times and boot time.
//   Gate: Finds the densest two-minute start cluster, then reports only later outliers beyond the
//         recovered five-minute/boot conditions.
//   Output: Emits S_Restarted console/debug evidence, except captured PcaSvc exclusion produces
//           only an ignored-late-start diagnostic.
//   Failure: Fewer than two nonzero times or required zero boot suppresses analysis; query failures
//            leave older map entries intact.

namespace ocean::reconstructed::shared_service_restarts {
using Handle=std::uint64_t;
struct Time {
    std::uint64_t wall=0;
    std::int64_t seconds=0;
    std::uint64_t location=0;
};
struct Row {
    ByteString service;
    Time start;
}; //original40-byte row
struct Error {
    bool present=false;
    ByteString detail;
};
template<class T>struct Read {
    T value;
    Error error;
};
struct ServiceStatus {
    std::array<std::uint32_t,9> words{};
}; //36-byte SERVICE_STATUS_PROCESS
struct ProcessTimes {
    std::uint64_t creation=0,exit=0,kernel=0,user=0;
};
struct Globals {
    std::map<ByteString,Time>* service_times=nullptr; //5728ef8; existing map, never cleared here
    const std::set<ByteString>* late_start_exclusions=nullptr; //5728ef0; actual map[string]struct{}, presence only
    Time boot; //572e0c0/c8/d0, direct cached shared cutoff
};
struct Contracts {
    virtual Read<Handle> open_scm(std::uint32_t access)=0;
    virtual Read<Handle> open_service_w(Handle,const ByteString&,std::uint32_t access)=0;
    virtual Read<ServiceStatus> query_service_status_ex(Handle,std::uint32_t info_class,std::uint32_t bytes)=0;
    virtual void close_service_handle_ignoring_error(Handle)=0;
    virtual Read<Handle> open_process(std::uint32_t access,bool inherit,std::uint32_t pid)=0;
    virtual Read<ProcessTimes> get_process_times(Handle)=0;
    virtual void close_process_handle_ignoring_error(Handle)=0;
    virtual std::uint64_t local_timezone_pointer()=0;
    virtual bool before(const Time&,const Time&)=0;
    virtual bool after(const Time&,const Time&)=0;
    virtual std::int64_t sub_ns(const Time&,const Time&)=0;
    virtual Time add_ns(const Time&,std::int64_t)=0;
    virtual std::int64_t since_ns(const Time&)=0;
    virtual ByteString format_time(const Time&,const ByteString&)=0;
    virtual void print_service_restart(const ByteString&)=0;
    virtual void print_ignored_late_start(const ByteString& service,const ByteString& rfc3339_time)=0;
    virtual void append_restart_debug(const ByteString& service,const Time& start,std::int64_t duration_ns)=0;
    virtual void recovery_scope(const ByteString& site,const std::function<void()>& body)=0;
    [[noreturn]] virtual void panic_nil_service_map()=0;
};
struct ScopeClose {std::function<void()> close;~ScopeClose(){close();}};
std::set<ByteString> captured_late_start_exclusions(){return {"PcaSvc"};}
//Direct captured Go map bytes: used1, directory-length0, zero-size value type,
//one occupied group slot containing PcaSvc. Package init is the sole direct
//pointer writer found in this package; caller still supplies the actual set.
Time creation_filetime_to_time(std::uint64_t filetime,Contracts& rt){
    //Preserve original uint64 FILETIME.Nanoseconds wrap before signed Unix
    //normalization. Very old/far-future FILETIMEs need not represent real dates.
    const auto wrapped=(filetime-116444736000000000ULL)*100ULL;
    const auto ns=std::bit_cast<std::int64_t>(wrapped);
    auto seconds=ns/1000000000LL;auto remainder=ns%1000000000LL;
    if(remainder<0){--seconds;remainder+=1000000000LL;}
    return {std::uint64_t(remainder),seconds+62135596800LL,rt.local_timezone_pointer()};
}
Read<Time> process_creation_time(Contracts& rt,std::uint32_t pid){ //tgRVwpGh5@12d8920
    Read<Time> result;
    rt.recovery_scope("tgRVwpGh5",[&]{
        const auto process=rt.open_process(0x1000,false,pid);
        if(process.error.present){result.error=process.error;return;}
        ScopeClose close{[&]{rt.close_process_handle_ignoring_error(process.value);}};
        const auto times=rt.get_process_times(process.value);
        if(times.error.present){result.error=times.error;return;}
        result.value=creation_filetime_to_time(times.value.creation,rt);
    });
    //App wraps native OpenProcess/GetProcessTimes errors before returning a
    //zero Time+non-nil error; error wrapper text is a display detail. Exit,
    //kernel and user FILETIMEs are requested but discarded.
    return result;
}
void query_service_start(Contracts& rt,Globals& globals,const ByteString& name){ //nqM8llM@12d8140
    rt.recovery_scope("nqM8llM",[&]{
        const auto manager=rt.open_scm(4);if(manager.error.present)return;
        ScopeClose close_manager{[&]{rt.close_service_handle_ignoring_error(manager.value);}};
        const auto service=rt.open_service_w(manager.value,name,5);if(service.error.present)return;
        ScopeClose close_service{[&]{rt.close_service_handle_ignoring_error(service.value);}};
        const auto status=rt.query_service_status_ex(service.value,0,36);if(status.error.present)return;
        const auto time=process_creation_time(rt,status.value.words[7]);if(time.error.present)return;
        if(globals.service_times==nullptr)rt.panic_nil_service_map();
        (*globals.service_times)[name]=time.value;
        //Only PID (DWORD at28) is used; service running state is not checked.
        //PID0 is forwarded. Read failures do not erase an older map entry.
    });
}
struct Cluster {
    std::size_t count=0,begin=0,end=0;
};
Cluster densest_window(Contracts& rt,const std::vector<Row>& sorted,std::int64_t maximum_span){ //htBlzsaVL6lQ@12d6240
    Cluster best;
    for(std::size_t begin=0;begin<sorted.size();++begin){
        auto end=begin;
        while(end<sorted.size() && rt.sub_ns(sorted[end].start,sorted[begin].start)<=maximum_span)++end;
        if(end-begin>best.count)best={end-begin,begin,end}; //earliest equal-sized cluster wins
    }
    return best;
}
bool zero(const Time& time){return time.wall==0 && time.seconds==0;}
std::int64_t original_abs(std::int64_t value){
    if(value>=0)return value;
    return std::bit_cast<std::int64_t>(0ULL-std::bit_cast<std::uint64_t>(value)); //INT64_MIN stays negative
}
void report(Contracts& rt,const Globals& globals,const Row& row){ //g0k2jYThpTvc@12d63a0
    if(globals.late_start_exclusions && globals.late_start_exclusions->find(row.service)!=globals.late_start_exclusions->end()){
        rt.print_ignored_late_start(row.service,rt.format_time(row.start,"2006-01-02T15:04:05.999999999Z07:00"));return;
    }
    const auto elapsed=rt.since_ns(row.start); //negative allowed
    rt.print_service_restart(row.service);
    rt.append_restart_debug(row.service,row.start,elapsed);
    //Exact typed debug row: ["Detect","S_Restarted",service,GoTime,GoDuration].
    //No warning-string global write and no insertion into the exclusion map.
    //It is a trigger/demand-start exclusion input, not a deduplication set here.
}
void analyze(Contracts& rt,const Globals& globals){ //vv0yDT0Ka@12d7920
    rt.recovery_scope("vv0yDT0Ka",[&]{
        std::vector<Row> rows;
        if(globals.service_times)for(const auto& [name,time]:*globals.service_times)if(!zero(time))rows.push_back({name,time});
        if(rows.size()<2)return;
        std::sort(rows.begin(),rows.end(),[&](const Row& a,const Row& b){return rt.before(a.start,b.start);}); //ties unspecified
        constexpr std::int64_t two_minutes=120000000000LL,five_minutes=300000000000LL;
        const auto cluster=densest_window(rt,rows,two_minutes);
        if(cluster.count*2<rows.size()){
            if(zero(globals.boot))return;
            for(const auto& row:rows){
                if(!rt.after(row.start,rt.add_ns(globals.boot,five_minutes)))continue;
                std::size_t neighbors=0;
                for(const auto& candidate:rows)if(original_abs(rt.sub_ns(candidate.start,row.start))<=two_minutes)++neighbors;
                if(neighbors<2)report(rt,globals,row); //self is included in neighbor count
            }
            return;
        }
        const auto& median=rows[cluster.begin+(cluster.end-cluster.begin)/2].start; //upper middle for even cluster
        for(const auto& row:rows){
            if(original_abs(rt.sub_ns(row.start,median))<=five_minutes)continue;
            if(!rt.after(row.start,rt.add_ns(median,five_minutes)))continue; //earlier outliers excluded
            if(!zero(globals.boot)){
                if(rt.before(row.start,globals.boot))continue;
                if(!rt.after(row.start,rt.add_ns(globals.boot,five_minutes)))continue;
            }
            report(rt,globals,row);
        }
    });
}
void check(Contracts& rt,Globals& globals){ //AbKf7uFX6z@12d5920, shared RServices2
    rt.recovery_scope("AbKf7uFX6z",[&]{
        for(const auto& name:{"SysMain","PcaSvc","EventLog","DPS","DusmSvc","CryptSvc"}){
            rt.recovery_scope("AbKf7uFX6z.func4",[&]{query_service_start(rt,globals,name);});
        }
        analyze(rt,globals);
    });
    //Start is the hosting process's creation time, not an SCM service-transition
    //event. Co-hosted services can have identical times. Existing map entries
    //and excluded trigger/demand-start services come from other collection flow.
}
//17 original dispatch/selection routes, original cluster helper and comparator
//body reviewed;21 original native collector/FILETIME/reporter routes. Native
//I/O/time/sort primitives synthetic. FILETIME arithmetic checked against every
//successful original process route. Recovery unwinding remains a runtime
//contract; source stays inside the VM, never compiled or executed.
}
