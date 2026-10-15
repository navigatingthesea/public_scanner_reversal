#include "../../common/review_contracts.hpp"
// Recovered behavior summary:
//   Input: Lines repeatedly scanned from the Windows hosts file.
//   Gate: Case-lowers each line and tests for the byte substring anticheat.ac.
//   Output: Records the first global alert reason/time, then continues polling every three seconds.
//   Failure: The recovered loop does not visibly branch on open error and defers closes to the
//            function activation.

namespace ocean::reconstructed {
// Original EGIdVaS7m0.IgaiQp @ 0x10bcc00.
void record_first_detection(RuntimeContracts& runtime,const ByteString& reason) {
 auto* state=runtime.globals().alert;
 if(state==nullptr || state->recorded) return;
 state->reason=reason;
 state->recorded=true;
 state->time=runtime.now();
 state->byte_48=0;
 // Original has no visible lock around this check/store. Do not add one silently.
}
// Original tVSorL.oJ1jMej5l0Cg @ 0x2015900.
void monitor_hosts_file(RuntimeContracts& runtime) {
 for(;;) {
  const auto opened=runtime.open_file("C:\\Windows\\System32\\drivers\\etc\\hosts",0,0);
  const auto file=opened.value; // Original does not visibly branch on open error.
  runtime.register_go_deferred_file_close(file);
  // Defer belongs to this function activation, not the loop iteration. Normal
  // iterations retain pending closes. A C++ RAII close here would change behavior.
  ByteString line;
  while(runtime.scanner_next(file,line)) {
   const auto lowered=runtime.to_lower(line);
   if(lowered.find("anticheat.ac")!=ByteString::npos) {
    record_first_detection(runtime,"bypass method detected on hosts file");
    break;
   }
  }
  runtime.sleep_nanoseconds(3000000000LL);
 }
}
}
