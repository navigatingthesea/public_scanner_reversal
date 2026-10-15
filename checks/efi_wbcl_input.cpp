#include "efi_evidence_types.hpp"
#include <bit>
#include <functional>
// Recovered behavior summary:
//   Input: Raw WBCL bytes returned by the Windows event-log provider.
//   Gate: Parses SpecID digest lengths and EFI boot-service application records with recovered
//         cursor/bounds behavior.
//   Output: Returns ordered image records with path, SHA-256, address, size, device nodes,
//           partition GUID, and drive type.
//   Failure: Collection or parse errors return explicit error/partial data; this parser does not
//            verify images against disk.

namespace ocean::reconstructed::efi_wbcl_input {
using efi_evidence::WbclImageRecord;
struct Error {ByteString text;};
struct BinaryResult {
    ByteString bytes;
    std::optional<Error> error;
};
struct Result {
    std::vector<WbclImageRecord> records;
    std::optional<Error> error;
};
struct DevicePath {
    ByteString path;
    std::vector<ByteString> nodes;
};
struct Contracts {
 virtual std::pair<std::uintptr_t,std::optional<Error>> open_hklm(const ByteString&,std::uint32_t)=0;
 virtual BinaryResult get_binary(std::uintptr_t,const ByteString&)=0;
 virtual void with_deferred_close(std::uintptr_t,const std::function<void()>&)=0;
 virtual void go_panic_bounds()=0;
 virtual DevicePath parse_device_path(const ByteString&)=0; //fcRCoHpyiIX@12cc940 separately reviewed
 virtual ByteString partition_guid_from_nodes(const std::vector<ByteString>&)=0;
 virtual ByteString drive_type_from_nodes(const std::vector<ByteString>&)=0;
};
static std::uint16_t u16(const ByteString& b, std::size_t p) {
 return static_cast<unsigned char>(b[p]) |
  (std::uint16_t(static_cast<unsigned char>(b[p+1])) << 8);
}
static std::uint32_t u32(const ByteString& b,std::size_t p){return u16(b,p)|(std::uint32_t(u16(b,p+2))<<16);}
static std::uint64_t u64(const ByteString& b,std::size_t p){return u32(b,p)|(std::uint64_t(u32(b,p+4))<<32);}
static ByteString hex(const ByteString& bytes) {
 ByteString out;
 constexpr char alphabet[]="0123456789abcdef";
 for(unsigned char c:bytes) {
  out+=alphabet[c>>4];
  out+=alphabet[c&15];
 }
 return out;
}
std::vector<WbclImageRecord> parse(Contracts& rt,const ByteString& bytes){ //dffVrJQEyy@12cb8c0
 std::vector<WbclImageRecord> result;if(bytes.size()<32)return result;
 const auto initial_size=u32(bytes,28);std::uint64_t offset=32ULL+initial_size;
 if(offset>bytes.size())return result;
 std::unordered_map<std::uint16_t,std::uint16_t> digest_lengths;
 if(initial_size>=29 && bytes.compare(32,16,ByteString("Spec ID Event03\0",16))==0){
  const auto algorithms=u32(bytes,32+24);std::uint64_t at=28;
  for(std::uint32_t i=0;i<algorithms && at+4<=initial_size;++i,at+=4)
   digest_lengths[u16(bytes,32+at)]=u16(bytes,32+at+2); //last duplicate wins
 }
 if(digest_lengths.empty())digest_lengths[11]=32; //captured fallback constant
 while(offset<bytes.size() && offset+12<=bytes.size()){
  const auto type=u32(bytes,offset+4); //PCR index at+0 is NOT filtered/read
  const auto digest_count=u32(bytes,offset+8);auto cursor=offset+12;ByteString sha256;
  for(std::uint32_t i=0;i<digest_count && cursor+2<=bytes.size();++i){
   const auto algorithm=u16(bytes,cursor);cursor+=2;
   const auto found=digest_lengths.find(algorithm);
   const auto length=found==digest_lengths.end()?0:found->second;
   if(length==0 || cursor+length>bytes.size())break;
   if(algorithm==11)sha256=hex(bytes.substr(cursor,length)); //not required length32
   cursor+=length;
  }
  //Unknown/truncated digest breaks ONLY inner loop. Original then interprets
  //bytes at CURRENT cursor as event size, even if digest list was incomplete.
  if(cursor+4>bytes.size())break;
  const auto size=u32(bytes,cursor);cursor+=4;const auto next=cursor+size;
  if(next>bytes.size())break;
  if(type==0x80000003U && size>31){
   const auto path_length=u64(bytes,cursor+24);const auto total=path_length+32;
   if(std::bit_cast<std::int64_t>(total)<=static_cast<std::int64_t>(size)){
    if(total>bytes.size()-cursor || total<32)rt.go_panic_bounds();
    const auto path=rt.parse_device_path(bytes.substr(cursor+32,total-32));
    result.push_back({static_cast<std::int64_t>(result.size()+1),path.path,sha256,
     u64(bytes,cursor+8)>>10,u64(bytes,cursor),path.nodes,
     rt.partition_guid_from_nodes(path.nodes),rt.drive_type_from_nodes(path.nodes)});
   }
  }
  offset=next;
 }return result;
}
Result collect(Contracts& rt){ //ApllxOqd@12cb4c0
 const auto [key,error]=rt.open_hklm(R"(SYSTEM\CurrentControlSet\Control\IntegrityServices)",1);
 if(error)return {{},error};
 Result result;
 rt.with_deferred_close(key,[&]{
  const auto value=rt.get_binary(key,"WBCL");
  if(value.error){result.error=value.error;return;}
  if(!value.bytes.empty())result.records=parse(rt,value.bytes);
 });return result;
}
//19 original parser routes with synthetic logs; SHA256/custom/short/duplicate
//digests, optional/malformed SpecID, truncation/event type/path bounds, size/address
//and ordinals.3 wrapper returns +1 deliberately stopped parser boundary. Device
//path/GUID/type providers are explicit dependencies, not claimed complete here.
//No first-event PCR/type/digest/version check; no cryptographic verification of
//measurements against loaded/disk files in THIS parser. Source never compiled/run.
}
