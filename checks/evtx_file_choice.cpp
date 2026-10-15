#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Stat results for the hardcoded System32 and Sysnative Application.evtx paths.
//   Gate: Selects the first path with no Stat error, otherwise filepath.Abs(Application.evtx).
//   Output: Returns exactly one path to the EVTX scanner.
//   Failure: Any Stat error triggers fallback and the final absolute-path error is ignored.

namespace ocean::reconstructed::shared_evtx_file_choice {
struct Contracts {
    virtual bool original_stat_has_error(const ByteString&)=0;
    virtual ByteString original_windows_filepath_absolute_ignore_error(const ByteString&)=0;
};
ByteString choose(Contracts& runtime) { //yWu@12a1740
    const ByteString system32="C:\\Windows\\System32\\winevt\\Logs\\Application.evtx";
    if(!runtime.original_stat_has_error(system32)) return system32;
    const ByteString sysnative="C:\\Windows\\Sysnative\\winevt\\Logs\\Application.evtx";
    if(!runtime.original_stat_has_error(sysnative)) return sysnative;
    return runtime.original_windows_filepath_absolute_ignore_error("Application.evtx");
}
// Any Stat error takes fallback (not only missing). No environment WINDIR lookup;
// hardcoded C:\Windows paths. Final filepath.Abs error ignored, no final Stat/read
// in chooser.3 original synthetic cases returned; Abs intercepted unchanged input
// in probe, not asserted original value. Native file metadata not queried by analysis.
// The parser/event producer is in windows_evtx_reader.cpp; ID/time/filter/report consumers are in the adjacent EVTX check sources.
// VM-only readable source never compiled/run.
}
