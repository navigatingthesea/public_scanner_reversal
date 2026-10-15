#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: The cached installation/reset reference time and source plus the shared boot time.
//   Gate: Source must be ResetEngine, SysReset, ResetLogs, or start with cluster(; same-boot or at
//         most roughly 48 hours old qualifies.
//   Output: Appends FactoryReset warning/debug data with source, formatted time, age, and scope.
//   Failure: Zero times and rejected sources suppress output; future age clamps to zero and
//            same-boot has no upper-age limit.

namespace ocean::reconstructed::shared_factory_reset {
struct Time {
    std::uint64_t wall=0;
    std::int64_t seconds=0;
    std::uint64_t location=0;
};
struct Reference {
    Time time;
    ByteString source;
};
struct Contracts{
 virtual Reference cached_install_reference_time()=0; //EeB6Y7KK_@f273e0, Sync.Once
 virtual std::int64_t since_ns(const Time&)=0;
 virtual Time add_ns(const Time&,std::int64_t)=0;
 virtual bool before(const Time&,const Time&)=0;
 virtual Time in_local(const Time&)=0;
 virtual ByteString format_time(const Time&,const ByteString&)=0;
 virtual ByteString human_duration(std::int64_t)=0; //PPEBuhDdvVhp, human_duration.cpp
 virtual void append_warning(const ByteString&)=0;
 virtual void append_debug(const std::vector<ByteString>&)=0;
};
bool zero(const Time& time){return time.wall==0 && time.seconds==0;}
bool accepted_source(const ByteString& source){ //EgPSBp@f2e540
 return source=="ResetEngine" || source=="SysReset" || source=="ResetLogs" || source.starts_with("cluster(");
 //Case-sensitive. Any cluster prefix qualifies, even "cluster(" alone and
 //clusters with no reset artifact name; closing parenthesis not required.
}
void check(Contracts& rt,const Time& shared_boot){ //AOqeamxFbv_7@129d300
 const auto reference=rt.cached_install_reference_time();
 if(zero(reference.time) || !accepted_source(reference.source))return;
 auto age=rt.since_ns(reference.time);if(age<0)age=0;
 bool same_boot=false;
 if(!zero(shared_boot))same_boot=!rt.before(reference.time,rt.add_ns(shared_boot,-120000000000LL));
 constexpr std::int64_t hour_ns=3600000000000LL;
 const double hours=double(age/hour_ns)+double(age%hour_ns)/double(hour_ns);
 const auto whole_days=static_cast<std::int64_t>(hours/24.0);
 if(!same_boot && whole_days>1)return; //approximately age<48h, using original floating/truncation formula
 const ByteString scope=same_boot?"Boot instance":"Out of instance";
 rt.append_warning("System Factory Reset:::"+scope+":::factory pc was detected 1 day ago");
 //"1 day ago" is literal text, independent of actual age, including future/old.
 const auto formatted=rt.format_time(rt.in_local(reference.time),"2006-01-02 15:04:05");
 const auto human=rt.human_duration(age);
 rt.append_debug({"Warning","FactoryReset",reference.source,formatted,human,scope});
 //Same-boot branch has no age upper bound. Reference exactly boot-120s qualifies.
 //Zero shared boot always uses the out-of-instance branch. No deduplication.
}
//Reference candidate collection/validation/cluster/priority/cache is in
//install_reference_time.cpp, registry conversions in install_registry_times.cpp.
//It considers registry InstallTime/InstallDate and creation times of system
//artifacts, reset artifacts and user paths; this callback does not re-read them.
//A reference source InstallTime/InstallDate alone is rejected by this classifier.
//Selected reference and source remain global cached values from that producer.
//18 source-classifier routes plus18 callback routes, six with the ORIGINAL
//source classifier integrated, confirm malformed cluster prefix, cutoff,48h
//boundary, future clamp and same-boot old ages. Reference/time/format providers
//synthetic; original decoder/age/output instructions interpreted in guest.
//Console/UI timing logger omitted under scope. Never compiled or run.
}
