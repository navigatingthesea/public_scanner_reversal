#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: The recovered Windows service account/configuration fields.
//   Gate: Compares the service identity against the captured expected account using the original
//         string predicate.
//   Output: Emits the service-account warning/debug row when it differs.
//   Failure: SCM open/query failures suppress the finding and close errors are ignored.

namespace ocean::reconstructed::shared_service_account {
template<class T>struct Read {
    T value{};
    bool error=false;
};
struct Contracts{
 virtual Read<ByteString> read_service_start_account(const ByteString&)=0;
 virtual bool go_unicode_equal_fold(const ByteString&,const ByteString&)=0;
 virtual void recover(const std::function<void()>& body,const std::function<void()>& on_panic)=0;
 virtual void print_text(const ByteString&)=0;
 virtual void print_fields(const std::vector<ByteString>&)=0;
 virtual void append_debug_account(const ByteString& service,const ByteString& account)=0;
};
void check(Contracts& rt){ //BPLpHaZKQz1@12be3c0; workerfunc7@12bef20
 rt.recover([&]{
  const std::pair<ByteString,ByteString> services[]={
   {"SysMain","LocalSystem"},{"EventLog","NT AUTHORITY\\LocalService"},
   {"PcaSvc","LocalSystem"},{"DusmSvc","NT AUTHORITY\\LocalService"}};
  for(const auto& [name,expected]:services){
   auto actual=rt.read_service_start_account(name);if(actual.error)continue;
   if(rt.go_unicode_equal_fold(actual.value,expected))continue;
   rt.print_text("service "+name+" manipulated:::Boot instance:::Service permissions were modified");
   rt.append_debug_account(name,actual.value);
  }
 },[&]{rt.print_fields({"Crash","Services_Permissions","Main permissions check failed"});});
 //Debug ["Detect","S_Manipulated",name,actualAccount]. No warning global.
 //Despite Permissions label, no ACL/token permission comparison takes place.
 //No SID resolution: equivalent account aliases can compare unequal.
}
//Five original callback routes and direct recovery handler. Read provider is
//r2rH1AJ@12bdc20, reconstructed separately in service_account_config_reader.cpp.
//Guest-only review source, never compiled or executed.
}
