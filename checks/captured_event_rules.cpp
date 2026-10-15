#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: The ten 64-byte rule records preserved from global 0x5663230.
//   Gate: No runtime predicate is applied here; this file projects each record to its label and
//         term list.
//   Output: Returns the captured Application Error matching rules consumed by the EVTX scan.
//   Failure: This snapshot does not establish the complete dynamic or server-supplied rule
//            universe.

namespace ocean::reconstructed::captured_event_rules {

struct Rule {
    ByteString label;
    std::vector<ByteString> terms;
};

std::vector<Rule> snapshot_rules() {
    return {
        {"Suspicious Injection Cheat", {"nunetplwiz.exe"}},
        {"Generic Bypass A", {"winrar.exe", "netplwiz.exe"}},
        {"Generic Bypass B", {"mstsc.exe"}},
        {"Suspicious Activity", {"nvidia app.exe", "radeonsoftware.exe"}},
        {"Generic Cheat injection",
         {"chrome.exe", "netplwiz.exe", "osk.exe", "lsass.exe", "desktop.exe",
          "winrar.exe", "shellhost.exe", "rundll32.exe", "radeonsoftware.exe",
          "notepad.exe", "spotify.exe", "wuauclt.exe", "sppsvc.exe",
          "chromesetup.exe", "mstsc.exe", "calc.exe", "write.exe",
          "googleupdate.exe", "nvidia app.exe", "gameoverlayui64.exe",
          "regsvr32.exe"}},
        {"Generic Bypass C",
         {"desktop.exe", "write.exe", "chromesetup.exe", "sppsvc.exe",
          "googleupdate.exe", "notepad.exe", "calc.exe", "dllhost.exe",
          "msconfig.exe", "mmc.exe", "mstsc.exe", "chrome.exe", "regsvr32.exe",
          "rundll32.exe", "radeonsoftware.exe", "nvidia app.exe", "osk.exe",
          "netplwiz.exe", "spotify.exe", "winrar.exe", "shellhost.exe",
          "gameoverlayui64.exe", "armourysocketserver.exe", "xboxpcapp.exe",
          "tbs_browser.exe", "asusdownloadlicense.exe", "accstd.exe",
          "python.exe"}},
        {"Suspicious Activity",
         {"armourysocketserver.exe", "xboxpcapp.exe", "tbs_browser.exe",
          "asusdownloadlicense.exe", "accstd.exe", "python.exe"}},
        {"Suspicious Crash A", {"sppsvc.exe"}},
        {"Suspicious Crash B", {"mstsc.exe"}},
        {"Abnormal crash occurred",
         {"desktop.exe", "write.exe", "chromesetup.exe", "sppsvc.exe",
          "googleupdate.exe", "notepad.exe", "calc.exe", "dllhost.exe",
          "msconfig.exe", "mmc.exe", "mstsc.exe", "chrome.exe", "winrar.exe",
          "shellhost.exe"}},
    };
}

// Snapshot globals 0x5663230/0x5663238/0x5663240 describe ten records with a
// 64-byte stride. The other three words at offsets 40..63 are retained in the
// evidence JSON but are not read by this EVTX callback.
// This is captured data, not proof of the full dynamic/server-rule universe.
// The previous 128-byte interpretation was discarded: original instruction
// 0x12a0c24 adds 0x40 to RDX, and the two-rule fixture produced two reports.
// Rule labels are scanner heuristics; a substring match does not prove actual
// injection, bypass, or execution intent.

}  // namespace ocean::reconstructed::captured_event_rules
