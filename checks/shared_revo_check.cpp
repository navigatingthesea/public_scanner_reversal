#include "../session/session_types.hpp"
#include <functional>
#include <bit>
// Recovered behavior summary:
//   Input: Revo-related Notifications data, two CloudStore blobs, UserAssist value names, one Revo
//          setting, and one uninstall key.
//   Gate: Counts case-lowered substring hits plus successful setting/key presence; Notifications
//         use raw binary fallback and UserAssist names are not ROT13-decoded.
//   Output: Appends one Revo warning carrying the wrapped combined count when it is positive.
//   Failure: Each registry source fails independently; there is no time, process, filesystem, or
//            execution-history gate.

namespace ocean::reconstructed::shared_revo {
using Handle=std::uint64_t;
template<class T>struct Read {
    T value{};
    bool error=false;
};
struct Contracts{
 virtual Read<Handle> open_key(Handle,const ByteString&,std::uint32_t access)=0;
 virtual Read<std::vector<ByteString>> value_names(Handle,std::int64_t count)=0;
 virtual Read<std::vector<ByteString>> subkey_names(Handle,std::int64_t count)=0;
 virtual Read<ByteString> string_value(Handle,const ByteString&)=0;
 virtual Read<ByteString> binary_value_as_raw_string(Handle,const ByteString&)=0;
 virtual void close_ignoring_error(Handle)=0;
 virtual ByteString go_unicode_to_lower(const ByteString&)=0;
 virtual void append_warning(const ByteString&)=0;
};
struct Close{Contracts& rt;Handle h;~Close(){rt.close_ignoring_error(h);}};
std::uint64_t notification_hits(Contracts& rt,const std::vector<ByteString>& needles){ //eVD4hsEjJ@12b2c60
 auto key=rt.open_key(0x80000002,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data",0x20019);
 if(key.error)return 0;Close close{rt,key.value};auto names=rt.value_names(key.value,-1);if(names.error)return 0;
 std::uint64_t count=0;
 for(const auto& name:names.value){
  auto raw=rt.string_value(key.value,name);
  if(raw.error){raw=rt.binary_value_as_raw_string(key.value,name);if(raw.error)continue;}
  const auto lower=rt.go_unicode_to_lower(raw.value);
  for(const auto& needle:needles)if(lower.find(needle)!=ByteString::npos){++count;break;}
 }
 return count; //one hit per value; binary fallback only after string-read ERROR
}
std::uint64_t cloudstore_hits(Contracts& rt,const ByteString& needle){ //aZLQ8HcffCoM@12b3140
 const ByteString paths[]={
  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\"
  "$de${9ead1854-30ed-44a5-a8f1-af0b4c114676}$$windows.data.unifiedtile."
  "localstarttilepropertiesmap\\Current",
  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\"
  "$de${9ead1854-30ed-44a5-a8f1-af0b4c114676}$$windows.data.unifiedtile."
  "roamedtilepropertiesmap\\Current"
 };
 const auto lower_needle=rt.go_unicode_to_lower(needle);std::uint64_t count=0;
 for(const auto& path:paths){
  auto key=rt.open_key(0x80000001,path,0x20019);if(key.error)continue;
  auto data=rt.binary_value_as_raw_string(key.value,"Data");rt.close_ignoring_error(key.value);
  if(!data.error && rt.go_unicode_to_lower(data.value).find(lower_needle)!=ByteString::npos)++count;
 }
 return count; //at most one per fixed blob, not number of occurrences
}
std::uint64_t userassist_name_hits(Contracts& rt,const ByteString& needle){ //hbXyYkxQUD@12b3320
 const ByteString path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
 auto root=rt.open_key(0x80000001,path,8);if(root.error)return 0;Close close{rt,root.value};
 auto children=rt.subkey_names(root.value,-1);if(children.error)return 0;
 const auto lower_needle=rt.go_unicode_to_lower(needle);std::uint64_t count=0;
 for(const auto& child:children.value){
  auto key=rt.open_key(0x80000001,path+"\\"+child+"\\Count",0x20019);if(key.error)continue;
  auto names=rt.value_names(key.value,-1);rt.close_ignoring_error(key.value);if(names.error)continue;
  for(const auto& name:names.value)if(rt.go_unicode_to_lower(name).find(lower_needle)!=ByteString::npos)++count;
 }
 return count; //NO ROT13 decode, value-data/run-count/time read or per-GUID dedup
}
std::uint64_t revo_setting_present(Contracts& rt){ //q8HxmdNeKfx@12b36c0
 const ByteString path="SOFTWARE\\VS Revo Group\\Revo Uninstaller\\General";
 auto key=rt.open_key(0x80000001,path,0x20019);
 if(key.error)key=rt.open_key(0x80000002,path,0x20019); //fallback only on OPEN error
 if(key.error)return 0;Close close{rt,key.value};
 return !rt.string_value(key.value,"AdButLink").error; //empty successful value counts
}
std::uint64_t revo_uninstall_key_present(Contracts& rt){ //c7zr0d8eO@12b3ea0
 auto key=rt.open_key(
  0x80000002,
  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
  "{A28DBDA2-3CC7-4ADC-8BFE-66D7743C6C97}_is1",0x20019);
 if(key.error)key=rt.open_key(
  0x80000002,
  "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
  "{A28DBDA2-3CC7-4ADC-8BFE-66D7743C6C97}_is1",0x20019);
 if(key.error)return 0;Close close{rt,key.value};return 1; //no values consulted
}
void check(Contracts& rt){ //A78aZiS2u@12b13c0
 std::uint64_t bits=notification_hits(rt,{"revouninstaller","revosetup","revo uninstaller"});
 bits+=cloudstore_hits(rt,"revouninstaller");bits+=userassist_name_hits(rt,"revouninstaller");
 bits+=revo_setting_present(rt);bits+=revo_uninstall_key_present(rt);
 const auto total=std::bit_cast<std::int64_t>(bits); //Go int64 wrapping sum
 if(total>0)rt.append_warning("Revo Uninstaller recently executed ("+std::to_string(total)+")");
 //WARNINGS global572e7a0 only; no Detect/debug record in this callback.
}
//All key/value names and lower needles decoded from original instructions.
//CloudStore paths are FIXED literal DefaultAccount GUID paths, not discovered
//SIDs. Both Notifications binary fallback and CloudStore scan RAW bytes as Go
//strings, with no UTF16 decode or NUL removal. Value names/bodies are transient;
//only the combined count is included in the emitted warning here.
//No timestamp, boot/session cutoff, process lookup or execution-history proof.
//Console/UI-only logging omitted under requested scope; collection/gates/report
//count preserved.34 original routes include28 callback/helper controls and6
//fallback/empty/ROT13/error cases. Forced-count routes verify overall sum15 and
//other-provider-only count1; these are not proof of native registry contents.
//Guest-only readable source; never compiled or run.
}
