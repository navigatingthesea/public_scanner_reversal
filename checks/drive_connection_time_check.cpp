#include "../session/session_types.hpp"
#include <vector>
// Recovered behavior summary:
//   Input: A drive root directory and Win32 entry creation timestamps.
//   Gate: The drive must be removable and have a nonexcluded entry created before the supplied
//         baseline.
//   Output: Returns the first qualifying creation time as connection evidence.
//   Failure: Directory or entry-info failures skip data; an unexpected Sys type follows the
//            recovered panic path.

namespace ocean::reconstructed::drive_connection_time_check {
struct Time {
    std::uint64_t wall,ext,location;
};
struct Result {Time value;bool error;};
struct Entry {ByteString name;};
struct Directory {
    std::vector<Entry> entries;
    bool error;
};
struct Detection {bool found;Time evidence;};
struct Contracts {
    virtual bool original_utf16_conversion_fails(const ByteString&)=0;
    virtual std::uint32_t original_get_drive_type_w(const ByteString&)=0;
    virtual Directory original_read_directory(const ByteString&)=0;
    // DirEntry.Info().Sys() must have captured *syscall.Win32FileAttributeData type.
    // Reads CreationTime LowDateTime at +4 and HighDateTime at +8, NOT ModTime.
    // Failed Info skips entry. Unexpected Sys type follows original type-assert panic.
    virtual Result original_entry_creation_time(const Entry&)=0;
    virtual Result original_stat_creation_time(const ByteString&)=0; //cDk@1298580 same Sys fields
    virtual bool original_before(Time,Time)=0;
    virtual bool original_after(Time,Time)=0;
};
bool removable(Contracts& runtime,ByteString drive) { //vfMH@1297e60
    if(!drive.empty() && drive.back()=='\\') drive.pop_back();
    drive+='\\'; //remove ONE slash, append ONE; slash spelling otherwise preserved
    if(runtime.original_utf16_conversion_fails(drive)) return false;
    return runtime.original_get_drive_type_w(drive)==2;
}
bool has_entry_created_before_baseline(Contracts& runtime,const ByteString& drive,Time baseline) {
    // asCg@12986c0: no recursive walk and no IsDir filter.
    const auto listing=runtime.original_read_directory(drive+"\\");
    if(listing.error) return false;
    for(const auto& entry:listing.entries) {
        if(entry.name=="$RECYCLE.BIN" || entry.name=="System Volume Information") continue;
        const auto created=runtime.original_entry_creation_time(entry);
        if(!created.error && runtime.original_before(created.value,baseline)) return true;
    }
    return false;
}
Detection check(Contracts& runtime,const ByteString& drive,Time baseline) { //wwRI@1299120
    const bool old_entry=has_entry_created_before_baseline(runtime,drive,baseline);
    const auto root=runtime.original_stat_creation_time(drive+"\\");
    const auto system_volume=runtime.original_stat_creation_time(drive+"\\System Volume Information");
    if(system_volume.error || !runtime.original_after(system_volume.value,baseline)) {
        const auto recycle=runtime.original_stat_creation_time(drive+"\\$RECYCLE.BIN");
        if(!recycle.error && runtime.original_after(recycle.value,baseline)
           && ((system_volume.value.wall==0 && system_volume.value.ext==0)
               || runtime.original_before(recycle.value,system_volume.value)))
            return {true,recycle.value};
        return {false,{}};
    }
    if(!old_entry && !root.error && runtime.original_after(root.value,baseline))
        return {false,{}};
    return {true,system_volume.value};
}
// Verified original helper branches:13 removable cases,8 entry cases,12 timestamp
// combinations. Providers synthetic; no real drive or reconstructed source ran.
// This feeds DriveConnected, not DriveFormatted. Case-sensitive excluded entry names.
}
