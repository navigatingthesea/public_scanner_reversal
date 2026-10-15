#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: HKLM TaskCache Author, Date, and Path values plus current time and the global username.
//   Gate: Requires all three values, case-sensitive username containment, accepted absolute cleaned
//         path, a parsed date, and age strictly below 24 hours; future dates pass.
//   Output: Emits a TaskSched_Manual console/debug row with cleaned path, parsed time, and age.
//   Failure: Any read/date/path failure skips the task; there is no boot-time, task-action, or
//            execution check.

namespace ocean::reconstructed::shared_task_recent {
using Handle=std::uint64_t;
struct Time {
    std::uint64_t wall=0;
    std::int64_t seconds=0;
    std::uint64_t location=0;
};
template<class T>struct Read {
    T value{};
    bool error=false;
};
struct Contracts{
 virtual Read<Handle> open_key(Handle,const ByteString&,std::uint32_t)=0;
 virtual Read<std::vector<ByteString>> subkeys(Handle,std::int64_t)=0;
 virtual Read<ByteString> string_value(Handle,const ByteString&)=0;
 virtual void close_ignoring_error(Handle)=0;
 virtual Time now()=0;
 virtual std::int64_t subtract_ns(const Time&,const Time&)=0;
 virtual Read<Time> parse_go_time(const ByteString& layout,const ByteString& input)=0;
 virtual Time in_local(const Time&)=0;
 virtual ByteString unicode_trim_space(const ByteString&)=0;
 virtual bool go_windows_is_abs(const ByteString&)=0;
 virtual ByteString go_windows_clean(const ByteString&)=0;
 virtual void recover_silently(const std::function<void()>&)=0;
 virtual void print_text(const ByteString&)=0;
 virtual void append_debug_path_time_age(const ByteString&,const Time&,std::int64_t)=0;
};
Read<Time> parse_date(Contracts& rt,const ByteString& input){ //bSSHZ0@12c3980
 if(input.find('T')==ByteString::npos)return rt.parse_go_time("2006-01-02 15:04:05",input);
 const auto t=input.find('T');if(input.find('T',t+1)!=ByteString::npos)return{{},true}; //fmt.Errorf("invalid date format")
 const auto day=input.substr(0,t);auto tail=input.substr(t+1);
 if(tail.find('Z')!=ByteString::npos){
  tail.erase(std::remove(tail.begin(),tail.end(),'Z'),tail.end()); //ALL uppercase Z bytes, not suffix-only
  auto parsed=rt.parse_go_time("2006-01-02T15:04:05",day+"T"+tail);
  if(parsed.error)return{{},true};
  return{rt.in_local(parsed.value),false};
 }
 if(tail.find('-')!=ByteString::npos || tail.find('+')!=ByteString::npos){
  tail=tail.substr(0,tail.find('-'));tail=tail.substr(0,tail.find('+'));
 }
 return rt.parse_go_time("2006-01-02T15:04:05",day+"T"+tail);
 //Explicit +/- timezone offsets discarded; no offset adjustment is performed.
 //Go time.Parse accepts fractional seconds even without a fraction in layout.
 //Only uppercase-Z branch converts successful parsed instant into Local.
}
void check(Contracts& rt,const ByteString& global_username){ //OWIYTd@12c24c0
 rt.recover_silently([&]{
  const auto now=rt.now(); //once, before opening registry
  auto root=rt.open_key(0x80000002,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",8);
  if(root.error)return;
  struct Close{Contracts& rt;Handle h;~Close(){rt.close_ignoring_error(h);}} close{rt,root.value};
  auto names=rt.subkeys(root.value,-1);if(names.error)return;
  for(const auto& name:names.value){
   auto key=rt.open_key(root.value,name,1);if(key.error)continue;
   auto author=rt.string_value(key.value,"Author");
   auto date=rt.string_value(key.value,"Date");
   auto path=rt.string_value(key.value,"Path");
   rt.close_ignoring_error(key.value); //all THREE reads occur, even on an earlier error
   if(author.error)author.value.clear();if(date.error)date.value.clear();if(path.error)path.value.clear();
   if(author.value.empty() || date.value.empty() || path.value.empty())continue;
   if(author.value.find(global_username)==ByteString::npos)continue; //case-sensitive contains, not equality
   auto normalized=rt.unicode_trim_space(path.value);
   while(!normalized.empty() && normalized.back()=='"')normalized.pop_back();
   while(!normalized.empty() && normalized.front()=='"')normalized.erase(normalized.begin());
   if(!rt.go_windows_is_abs(normalized))continue;
   if(normalized.find_first_of("<>:*\"|?")!=ByteString::npos)continue;
   normalized=rt.go_windows_clean(normalized);
   auto created=parse_date(rt,date.value);if(created.error)continue;
   const auto age=rt.subtract_ns(now,created.value);
   if(age>=86400000000000LL)continue; //negative future age PASSES
   rt.print_text("Generic Bypass Method (Task Schedule):::Boot instance:::The user executed a manual scheduled task");
   rt.append_debug_path_time_age(normalized,created.value,age);
  }
 });
 //Debug ["Detect","TaskSched_Manual",cleanPath,GoTime(parsedDate),GoDuration(age)].
 //No shared boot-time comparison, task execution lookup, Actions read, warning
 //global or dedup. IsAbs followed by forbidden ':' rejects drive-letter paths;
 //ordinary relative TaskCache task names also fail. UNC paths can pass.
}
//Thirty-five original callback routes plus14 date-helper routes. Synthetic
//registry/date/time providers, actual case-sensitive literal comparisons and
//ten concrete Windows path categories. Forced earlier predicate routes are
//control-flow coverage, not proof of natural reachability. Standard path,
//Unicode/time/recovery contracts remain explicit. Guest-only source, no compile/run.
}
