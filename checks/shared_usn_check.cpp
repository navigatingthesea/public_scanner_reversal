#include "../session/session_types.hpp"
#include <array>
#include <vector>
#include <functional>
// Recovered behavior summary:
//   Input: Fixed-drive letters, filesystem names, $UsnJrnl:$J metadata, and the shared boot cutoff.
//   Gate: Requires DRIVE_FIXED, exact NTFS, a regular journal stream, and ModTime strictly after
//         boot.
//   Output: Emits a Journal_D report/debug row with drive and age.
//   Failure: Native/stat failures return empty evidence; no journal records or deletion event are
//            read.

namespace ocean::reconstructed::shared_usn {
using Address=std::uint64_t;
struct Time {
    std::uint64_t wall=0;
    std::int64_t seconds=0;
    Address location=0;
};
struct FileInfo {
    bool stat_error=false,regular=false;
    Time modification_time;
};
struct Contracts {
    virtual std::vector<std::uint16_t> windows_string_to_utf16(const ByteString&)=0;
    virtual std::uint64_t get_drive_type_w(const std::uint16_t* root)=0;
    virtual void get_volume_information_w(const std::uint16_t* root,std::uint16_t* volume_name,std::uint32_t volume_units,
        std::uint32_t* serial,std::uint32_t* max_component,
        std::uint32_t* filesystem_flags,std::uint16_t* filesystem_name,
        std::uint32_t filesystem_units)=0;
    virtual ByteString windows_utf16_to_string(const std::uint16_t*,std::size_t)=0;
    virtual FileInfo stat_file(const ByteString& path)=0;
    virtual Time shared_boot_cutoff()=0; //572e0c0/c8/d0; direct cached value, no host-info fallback here
    virtual Address local_timezone_pointer()=0;
    virtual Address utc_timezone_singleton_pointer()=0;
    virtual bool time_after(const Time&,const Time&)=0;
    virtual std::int64_t time_since_ns(const Time&)=0;
    virtual ByteString human_duration(std::int64_t)=0; //human_duration.cpp, PPEBuhDdvVhp
    virtual ByteString format_time(const Time&,const ByteString& layout)=0;
    virtual void print_text(const ByteString&)=0;
    virtual void append_debug(const std::vector<ByteString>&)=0;
    virtual void original_recovery_scope(const std::function<void()>& body)=0; //original deferred handlers print crash details
    [[noreturn]] virtual void panic_empty_utf16_slice()=0;
};
ByteString filesystem_name(Contracts& rt,char letter){ //aYsXaVf@12ca0a0
    ByteString result;
    rt.original_recovery_scope([&]{
        const auto root=rt.windows_string_to_utf16(ByteString(1,letter)+":\\");
        if(root.empty())rt.panic_empty_utf16_slice();
        std::array<std::uint16_t,255> buffer{};
        rt.get_volume_information_w(root.data(),buffer.data(),255,nullptr,nullptr,nullptr,buffer.data(),255);
        //Volume-name and filesystem-name outputs intentionally ALIAS the same
        //255-code-unit buffer. Native return/error is ignored. Other outputs null.
        result=rt.windows_utf16_to_string(buffer.data(),buffer.size());
    });
    return result;
}
std::vector<ByteString> fixed_ntfs_drive_letters(Contracts& rt){ //u0FKy3IJT@12c9c00
    std::vector<ByteString> result;
    rt.original_recovery_scope([&]{
        std::vector<ByteString> pending;
        for(char letter='A';letter<='Z';++letter){
            const auto root=rt.windows_string_to_utf16(ByteString(1,letter)+":\\");
            if(root.empty())rt.panic_empty_utf16_slice();
            if(rt.get_drive_type_w(root.data())!=3)continue; //DRIVE_FIXED only
            if(filesystem_name(rt,letter)=="NTFS")pending.emplace_back(1,letter); //case-sensitive exact equality
        }
        result=std::move(pending); //Go return slots committed only after the entire loop
    });
    return result; //recovered earlier panic leaves zero/nil return, not partial pending letters
}
Time journal_modification_time(Contracts& rt,const ByteString& drive){ //eTCp55a26uz7@12c9300
    Time result;
    rt.original_recovery_scope([&]{
        const auto info=rt.stat_file("\\\\.\\"+drive+":\\$Extend\\$UsnJrnl:$J");
        if(!info.stat_error && info.regular)result=info.modification_time;
    });
    return result;
    //FileInfo.Mode -> IsRegular, then FileInfo.ModTime. This is NOT CreationTime,
    //AccessTime or a USN record timestamp. Stat error/nonregular returns zero.
    //No open/read of the journal's data or individual USN entries in this helper.
}
Time in_local_timezone(Contracts& rt,Time time){
    if((time.wall>>63)!=0){
        time.seconds=std::int64_t(((time.wall&0x7fffffffffffffffULL)>>30)+0xdd7b17f80ULL);
        time.wall&=0x3fffffffULL; //strip monotonic representation, keep nanoseconds
    }
    const auto local=rt.local_timezone_pointer();
    time.location=local==rt.utc_timezone_singleton_pointer()?0:local;
    return time;
}
void check(Contracts& rt){ //OcgNuIK9YVq@12c9620, shared CheckUSN callback
    rt.original_recovery_scope([&]{
        for(const auto& drive:fixed_ntfs_drive_letters(rt)){
            const auto modified=in_local_timezone(rt,journal_modification_time(rt,drive));
            if(!rt.time_after(modified,rt.shared_boot_cutoff()))continue;
            const auto age=rt.human_duration(rt.time_since_ns(modified));
            const auto timestamp=rt.format_time(modified,"2006-01-02 15:04:05");
            rt.print_text("Journal Deletion:::Boot instance:::USN Journal for drive "+drive+" was deleted "+age+" ago ("+timestamp+")");
            rt.append_debug({"Detect","Journal_D",drive,age});
        }
    });
    //No separate zero-time gate, no historical journal comparison, deletion
    //event search, journal-ID query or journal-record collection. The deletion
    //claim is the app's interpretation of ModTime > cached boot cutoff. Date is
    //printed; Detect debug stores drive+age only. Warning-string global untouched.
    //The age helper already includes "ago"; caller adds another "ago" literally.
}
//26 original fixtures:25 returns plus one expected bounds panic for an invalid
//synthetic empty UTF16 conversion. Covers all26 letters, type/FS selection,
//GetVolumeInformationW name verified from captured procedure metadata, aliased
//buffers, ignored error, Stat/Mode/ModTime and root/monotonic branches. Primitive
//FileInfo/time/native providers synthetic; runtime unwind is a separate contract.
//Guest-only source, never compiled or executed.
}
