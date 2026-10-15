#include "../session/session_types.hpp"
#include <array>
// Recovered behavior summary:
//   Input: Six bytes read at NtCreateFile in the SysMain service process.
//   Gate: Requires exact bytes B8 01 00 00 C0 C3; extra returned bytes are ignored.
//   Output: Emits the SysMain signature debug row with the first six bytes.
//   Failure: Service PID/export/module/read failures suppress output; this check does not modify
//            memory.

namespace ocean::reconstructed::sysmain_signature_review {
struct RemoteBytes {
    ByteString bytes;
    bool has_error=false;
};
struct InspectionContracts {
 // NN9p33oaT@f244a0 is reviewed in app/collection/service_pid.cpp:
 // SCM access1, service access4, QueryServiceStatusEx info0; uint32 PID28.
 // Real native outcomes/defers remain that module's contracts.
 virtual std::uint32_t original_service_pid(const ByteString& service_name)=0;
 // e986Cnb2g@1261c20: remote function-byte reader. Address resolution,
 // access/read/native failure paths are explicit OS and remote-memory provider contracts; the
 // application-side six-byte predicate is complete here.
 virtual RemoteBytes original_remote_function_bytes(std::uint32_t pid,const ByteString& function_name)=0;
 virtual void original_console_status_on_match()=0; //intercepted logger; GUI/status out of scope
 virtual void append_debug(const std::vector<ByteString>&)=0; //572e8e0 -> DEBUG_DETECTIONS
};
// ACpZILF@12609e0 checks six specific bytes at NtCreateFile in SysMain.
// It does not treat every altered prologue as a match. Extra bytes are ignored.
void check(InspectionContracts& r) {
 const auto pid=r.original_service_pid("SysMain");if(pid==0) return;
 const auto read=r.original_remote_function_bytes(pid,"NtCreateFile");
 if(read.has_error || read.bytes.size()<6) return;
 constexpr std::array<unsigned char,6> pattern{{0xb8,0x01,0x00,0x00,0xc0,0xc3}};
 for(std::size_t k=0;k<pattern.size();++k)
  if(static_cast<unsigned char>(read.bytes[k])!=pattern[k]) return;
 r.original_console_status_on_match();
 // Original helper zbn@1263700 formats each of the FIRST SIX bytes as %02X
 // and joins with spaces. Equality above fixes the exact displayed values.
 r.append_debug({"Detect","SysMainNtCreateFilePatch",
  "PID="+std::to_string(pid)+" Bytes=B8 01 00 00 C0 C3"});
}
// This caller creates a debug row, no WARNINGS entry. No service opening,
// native API implementation, memory patching or source execution is provided.
}
