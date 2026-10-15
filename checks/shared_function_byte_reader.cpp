#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: A PID, remote address/length, local ntdll export RVA, and target process module list.
//   Gate: Rejects invalid scalar inputs and SysWOW64 module paths, then reads from the target ntdll
//         base plus local RVA.
//   Output: Returns the exact nonempty remote byte slice or an explicit error.
//   Failure: Open/read/module/RVA failures propagate; partial bytes with a read error are discarded
//            and oversize results retain panic behavior.

namespace ocean::reconstructed::shared_function_byte_review {
struct ErrorWords {std::uint64_t type=0,data=0;bool present()const{return type!=0;}};
struct Bytes {
    std::vector<std::uint8_t> data;
    GoInt original_capacity=0;
    bool nil_backing=true;
};
struct ReadResult {
    Bytes value;
    ErrorWords error;
};
struct OpenResult {
    std::uint64_t handle=0;
    ErrorWords error;
};
struct NativeRead {
    std::vector<std::uint8_t> buffer;
    std::uint64_t bytes_read=0;
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
struct ReaderContracts {
 virtual ByteString original_lower_utf8(const ByteString&)=0;
 virtual ErrorWords original_error_text(const ByteString&)=0;
 virtual ErrorWords original_error_with_uint32_pid(const ByteString& format,std::uint32_t)=0;
 virtual OpenResult original_open_process(std::uint32_t access,bool inherit,std::uint32_t pid)=0;
 virtual NativeRead original_read_process_memory(std::uint64_t handle,std::uint64_t address,GoInt length)=0;
 virtual void original_close_handle_ignoring_error(std::uint64_t)=0;
 virtual ReadResult original_handle_defer_scope(std::uint64_t handle,const std::function<ReadResult()>&)=0;
 [[noreturn]] virtual void original_panic_bounds()=0;
 virtual RVAResult original_local_ntdll_function_rva(const ByteString& name)=0;
 virtual ModuleResult original_find_process_module(std::uint32_t,const ByteString& name)=0;
};
// mR1toyt@1263040. A substring heuristic, no IsWow64Process query or
// architecture/signature check here. It lowercases but does not change slashes.
bool rejects_module_path(ReaderContracts& r,const ByteString& full_path) {
 return r.original_lower_utf8(full_path).find("\\syswow64\\")!=ByteString::npos;
}
// ey9WPAc@12631a0. PID guard uses32bits; address64bits; length SIGNED64bits,
// confirmed test eax /test rbx /test rcx +jg at12631e4..12631f0.
ReadResult read_process_bytes(ReaderContracts& r,std::uint32_t pid,std::uint64_t address,GoInt length) {
 if(pid==0 || address==0 || length<=0) return {{},r.original_error_text("invalid read")};
 const auto opened=r.original_open_process(0x410,false,pid);
 if(opened.error.present()) return {{},opened.error};
 return r.original_handle_defer_scope(opened.handle,[&]()->ReadResult {
  const auto read=r.original_read_process_memory(opened.handle,address,length);
  if(read.error.present()) return {{},read.error}; //discard partial bytes on error
  if(read.bytes_read==0) return {{},r.original_error_text("empty read")};
  if(read.bytes_read>static_cast<std::uint64_t>(length)) r.original_panic_bounds();
  Bytes out;out.nil_backing=false;out.original_capacity=length;
  out.data.assign(read.buffer.begin(),read.buffer.begin()+read.bytes_read);
  return {out,{}};
 }); //normal return calls CloseHandle; result/error ignored
}
// e986Cnb2g@1261c20. Relative offset is obtained from LOCAL ntdll export;
// remote module base +offset wraps uint64. No zero-offset/bounds check here.
ReadResult read_remote_ntdll_function(ReaderContracts& r,std::uint32_t pid,const ByteString& name) {
 const auto local=r.original_local_ntdll_function_rva(name);
 if(local.error.present()) return {{},local.error};
 const auto remote=r.original_find_process_module(pid,"ntdll.dll");
 if(!remote.found) return {{},r.original_error_with_uint32_pid("ntdll.dll not found in pid %d",pid)};
 if(rejects_module_path(r,remote.full_path))
  return {{},r.original_error_with_uint32_pid("skipping wow64 ntdll in pid %d",pid)};
 return read_process_bytes(r,pid,remote.base+local.offset,16);
}
// Provider outlines from original p6@1262620 and_2r@1262ce0, not complete
// native-provider proofs yet: local library load +GetProcAddress, subtract
// local module handle/base; deferred unload. Remote Toolhelp snapshot flags
// 0x18, MODULEENTRY32W Size1080; names256UTF16 at48, exe path260 at560,
// base at24; lowercase exact name match, first matching entry returns.
// Snapshot/native enum/export/UTF16/load/unload/real process-read/error/panic
// paths are still contracts. No platform APIs are implemented in this source.
}
