#include "../session/session_types.hpp"
#include <vector>
// Recovered behavior summary:
//   Input: Enumerated drives, shared boot baseline, connection-time evidence, and volume-creation
//          evidence.
//   Gate: Skips exact C: and nonremovable drives; the two evidence predicates are independent.
//   Output: Emits DriveConnected and/or DriveFormatted report/debug rows for each qualifying input
//           row.
//   Failure: Enumeration failure aborts the scan; recovery handlers emit fixed crash records.

namespace ocean::reconstructed::drive_connected_formatted_flow {
struct Time {
    std::uint64_t wall,ext,location;
};
struct Drive {
    ByteString path;
}; //input record64 bytes, path GoString+16
struct Drives {
    std::vector<Drive> values;
    bool error;
};
struct Evidence {bool detected;Time time;};
struct Contracts {
    virtual Drives original_enumerate_drives()=0; //reviewed drive_enumerator.cpp@1205880
    virtual bool reviewed_removable_drive(const ByteString&)=0;
    virtual Evidence reviewed_drive_connection_time(const ByteString&,Time)=0;
    virtual Evidence reviewed_volume_creation_time(const ByteString&,Time)=0;
    virtual std::int64_t original_time_since(Time)=0;
    virtual void original_report_line(const ByteString&)=0;
    virtual void original_append_structured(const ByteString& category,const ByteString& name,
        const ByteString& drive,Time,const ByteString& elapsed)=0; //572e8e0
    virtual void original_register_recovery(const ByteString& label,const ByteString& message)=0;
};
ByteString duration(std::int64_t nanoseconds) { //gnBIE@1297f00
    const auto whole_seconds=nanoseconds/1000000000;
    const auto hours=whole_seconds/3600;
    const auto minutes=(whole_seconds%3600)/60;
    const auto seconds=whole_seconds%60;
    const auto unsigned_text=[](std::int64_t value) {return std::to_string(static_cast<std::uint64_t>(value));};
    if(hours>0) return unsigned_text(hours)+"h"+unsigned_text(minutes)+"m"+unsigned_text(seconds)+"s";
    if(minutes>0) return unsigned_text(minutes)+"m"+unsigned_text(seconds)+"s";
    return unsigned_text(seconds)+"s"; //negative remainder rendered unsigned in original
}
void check(Contracts& runtime,Time baseline) { //DRnPp@1299640,func2@12996e0
    // Exact recovery strings separately verified and supplied by generated report.
    runtime.original_register_recovery("FormatUSB","Main drive check failed");
    const auto drives=runtime.original_enumerate_drives();
    if(drives.error) return;
    runtime.original_register_recovery("FormatUSB_DriveCheck","Failed processing drive partitions");
    for(const auto& drive:drives.values) {
        if(drive.path=="C:" || !runtime.reviewed_removable_drive(drive.path)) continue;
        const auto connected=runtime.reviewed_drive_connection_time(drive.path,baseline);
        if(connected.detected) {
            const auto elapsed=duration(runtime.original_time_since(connected.time));
            runtime.original_report_line("Bypass Method (Drive Connected):::Boot instance:::The user connected a drive since boot");
            runtime.original_append_structured("Detect","DriveConnected",drive.path,connected.time,elapsed);
        }
        const auto formatted=runtime.reviewed_volume_creation_time(drive.path,baseline);
        if(formatted.detected) {
            const auto elapsed=duration(runtime.original_time_since(formatted.time));
            runtime.original_report_line("Bypass Method (Drive Formatting):::Boot instance:::The user formatted a drive since boot");
            runtime.original_append_structured("Detect","DriveFormatted",drive.path,formatted.time,elapsed);
        }
    }
}
// Independent predicates:both can emit for one drive. No dedup across drive input
// rows. Uppercase C: is exact skip; lowercase c: reaches GetDriveType. Enumeration
// error suppresses scan; recover closures discard panic value and emit fixed Crash
// rows.10 original output/iteration fixtures and12 duration cases returned.
// Heuristic labels do not establish a connection or formatting operation occurred.
// Raw drive record producer reviewed in drive_enumerator.cpp; logger transport remains separate.
// VM-only review C++; never compiled or run.
}
