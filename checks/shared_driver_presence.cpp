#include "../session/session_types.hpp"
#include <array>
#include <vector>
#include <functional>
// Recovered behavior summary:
//   Input: EnumDeviceDrivers output, driver names/paths, and a previously built hashed process
//          inventory.
//   Gate: Looks for lowercase fileinfo.sys and the intentionally mismatched mixed-case
//         SysmonDrv.sys needle; also requires Sysmon PID > 1 for one branch.
//   Output: Emits Sysmon-driver-missing and/or fileinfo-missing report/debug rows.
//   Failure: Enumeration/processing/root recovery paths emit fixed crash records; native return
//            statuses are otherwise ignored.

namespace ocean::reconstructed::shared_driver_presence {
using Address=std::uint64_t;
struct DriverFlags {
    bool sysmon=false,file_info=false;
};
struct Contracts {
    virtual void enum_device_drivers(Address* zero_initialized_array,std::uint32_t requested_bytes,std::uint32_t& returned_bytes)=0;
    virtual void driver_base_name_a(Address,std::array<unsigned char,256>&)=0;
    virtual void driver_file_name_a(Address,std::array<unsigned char,256>&)=0;
    virtual ByteString go_to_lower(const ByteString&)=0;
    virtual std::int64_t pid_from_hashed_inventory(const ByteString& hash)=0;
    virtual void print_text(const ByteString&)=0;
    virtual void print_fields(const std::vector<ByteString>&)=0;
    virtual void append_detect_debug(const ByteString& tag,bool sysmon,bool file_info)=0;
    virtual void go_recovery_scope(const std::function<void()>& body,const std::function<void()>& recovered_handler)=0;
    [[noreturn]] virtual void panic_driver_index()=0;
};
ByteString bounded_c_string(const std::array<unsigned char,256>& bytes){
    std::size_t length=0;while(length<bytes.size() && bytes[length]!=0)++length;
    return ByteString(reinterpret_cast<const char*>(bytes.data()),length);
}
void enumerate(Contracts& rt,std::array<Address,1024>& bases,std::uint32_t& bytes){ //IMxu1zUTJ.func2@1264720
    rt.go_recovery_scope([&]{rt.enum_device_drivers(bases.data(),1024,bytes);},[&]{
        rt.print_fields({"Crash","DBypass_EnumDeviceDrivers","Failed to enumerate device drivers"});
    });
    //The API return/status is ignored. Requested size is1024 BYTES although the
    //Go allocation holds1024 64-bit addresses. No resize/retry for required size.
}
void inspect_drivers(Contracts& rt,const std::array<Address,1024>& bases,std::uint32_t count,DriverFlags& flags){ //func3@1264120
    rt.go_recovery_scope([&]{
        for(std::uint32_t index=0;index<count;++index){
            std::array<unsigned char,256> name{};
            if(index>=bases.size())rt.panic_driver_index();
            rt.driver_base_name_a(bases[index],name);
            if(bounded_c_string(name).empty())continue;
            std::array<unsigned char,256> path{};
            rt.driver_file_name_a(bases[index],path);
            const auto raw_path=bounded_c_string(path);
            if(raw_path.empty())continue;
            const auto lower_path=rt.go_to_lower(raw_path);
            if(lower_path.find("fileinfo.sys")!=ByteString::npos)flags.file_info=true;
            if(lower_path.find("SysmonDrv.sys")!=ByteString::npos)flags.sysmon=true;
            //Captured mixed-case Sysmon needle is compared to a lowercased
            //path, case-sensitively. Preserve that mismatch exactly.
        }
    },[&]{rt.print_fields({"Crash","DBypass_DriverProcessing","Failed to process driver information"});});
    //Both name/path APIs' return values are ignored; nonempty written buffers
    //still count after status0. Basename content is only a nonempty gate. No
    //driver file is opened/hashed and no signature or driver memory is read here.
}
void check(Contracts& rt){ //IMxu1zUTJ@1263920
    rt.go_recovery_scope([&]{
        std::array<Address,1024> bases{};std::uint32_t returned_bytes=0;DriverFlags flags;
        enumerate(rt,bases,returned_bytes);
        inspect_drivers(rt,bases,returned_bytes>>2,flags); //original divides BYTES by4, indexes 8-byte pointers
        const auto pid=rt.pid_from_hashed_inventory("fffa2420bc8a93c75f342444c8b3f923a1f4a0eff21720790129d7defc75558a");
        //This salted digest exactly matches Sysmon64.exe in the previously
        //mapped service/process-name inventory. That map is not cleared by its
        //producer and this check does not verify freshness or process identity.
        if(pid>1 && !flags.sysmon){
            rt.print_text("Restarted SysMon Driver:::Boot instance:::the user restarted/disabled SysMon driver since last reboot");
            rt.append_detect_debug("SysmonDrvMissing",flags.sysmon,flags.file_info);
        }
        if(!flags.file_info){
            rt.print_text("Trace Prevention (fileinfo.sys):::Boot instance:::fileinfo.sys not enumerated among loaded kernel drivers");
            rt.append_detect_debug("FileInfoMissing",flags.sysmon,flags.file_info);
        }
    },[&]{rt.print_fields({"Crash","DBypass","Main function execution failed"});});
    //Writes Detect debug records, not the warning-string global. The text
    //claims a driver restart since boot, but this routine compares no historical
    //snapshot, start/stop event or boot timestamp.
}
//27 original root/provider/recovery-handler cases, plus15 original hashed-PID
//lookup/integer-conversion cases. Three API names verified from captured lazy
//procedure metadata. Synthetic native I/O only; recovery handlers tested
//directly with synthetic recover results, not a proof of Go runtime unwinding.
//Guest-only source, never compiled/executed.
}
