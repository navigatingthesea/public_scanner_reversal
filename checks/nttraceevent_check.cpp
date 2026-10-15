#include "../session/session_types.hpp"
#include <optional>
// Recovered behavior summary:
//   Input: Every enumerated process, its ntdll mapping, and eight bytes at the local NtTraceEvent
//          RVA.
//   Gate: Rejects PID 0 and SysWOW64; matches first byte C3 or B8 followed by any four-byte
//         immediate and C3.
//   Output: Appends a NtTraceEventPatch debug row with process name, PID, and all returned bytes.
//   Failure: Export/process/module/read errors skip data; this callback adds no warning-string
//            entry.

namespace ocean::reconstructed::nttraceevent_review {
struct ErrorWords {std::uint64_t type=0,data=0;bool present()const{return type!=0;}};
struct Process {
    std::uint32_t raw_pid_bits=0;
    std::uint64_t opaque_original_process=0;
};
struct ProcessList {
    std::vector<Process> values;
    ErrorWords error;
};
struct NameResult {
    ByteString value;
    ErrorWords error;
};
struct RVAResult {
    std::uint64_t offset=0;
    ErrorWords error;
};
struct ModuleResult {
    std::uint64_t base=0;
    ByteString full_path;
    bool found=false;
};
struct ReadResult {
    std::vector<std::uint8_t> bytes;
    ErrorWords error;
};
struct InspectionContracts {
 virtual RVAResult original_local_ntdll_function_rva(const ByteString&)=0;
 virtual ProcessList original_all_processes_with_background_context()=0;
 virtual NameResult original_process_name_with_background_context(const Process&)=0;
 virtual ModuleResult original_find_module(std::uint32_t,const ByteString&)=0;
 virtual bool original_reviewed_syswow64_path_predicate(const ByteString&)=0;
 virtual ReadResult original_reviewed_process_bytes(std::uint32_t,std::uint64_t,GoInt length)=0;
 virtual ByteString original_trim_unicode_space(const ByteString&)=0;
 virtual void original_console_status_on_match()=0;
 virtual void append_debug(const std::vector<ByteString>&)=0; //572e8e0 ->DEBUG_DETECTIONS
};
ByteString uppercase_hex_bytes(const std::vector<std::uint8_t>& bytes) {
 constexpr char digits[]="0123456789ABCDEF";ByteString out;
 for(std::size_t k=0;k<bytes.size();++k) {
  if(k) out+=' ';out+=digits[bytes[k]>>4];out+=digits[bytes[k]&15];
 }
 return out;
}
// LWpP9T3HE9@12613a0. NOT restricted to game/Java PIDs. Enum returns
// process objects and zero raw PID is skipped. Name-query error is ignored;
// module/read gates decide whether reporting happens.
void check(InspectionContracts& r) {
 const auto function=r.original_local_ntdll_function_rva("NtTraceEvent");
 if(function.error.present() || function.offset==0) return;
 const auto processes=r.original_all_processes_with_background_context();
 if(processes.error.present()) return;
 for(const auto& process:processes.values) {
  const auto pid=process.raw_pid_bits;if(pid==0) continue;
  const auto name=r.original_process_name_with_background_context(process);
  const auto module=r.original_find_module(pid,"ntdll.dll");
  if(!module.found || r.original_reviewed_syswow64_path_predicate(module.full_path)) continue;
  const auto read=r.original_reviewed_process_bytes(pid,module.base+function.offset,8);
  if(read.error.present() || read.bytes.empty()) continue;
  // First-byte RET, or MOV EAX,<ANY 4-byte immediate> followed by RET.
  // The four immediate bytes are not compared. Single-byte C3 can qualify.
  const bool match=read.bytes[0]==0xc3 ||
   (read.bytes.size()>=6 && read.bytes[0]==0xb8 && read.bytes[5]==0xc3);
  if(!match) continue;
  auto display_name=r.original_trim_unicode_space(name.value);
  if(display_name.empty()) display_name="unknown";
  r.original_console_status_on_match();
  r.append_debug({"Detect","NtTraceEventPatch",display_name+"["+std::to_string(pid)+
   "] Bytes="+uppercase_hex_bytes(read.bytes)});
 }
}
// Entire successful returned read (up to requested8 under actual reader) is
// hex-reported, not merely matched1/6byte prefix. Duplicate input processes
// append duplicates here. No WARNINGS entry in this caller. Real native
// process/name/module/export/read/runtime error paths remain contracts; final
// DEBUG_DETECTIONS normalizer performs its separately reviewed filtering.
}
