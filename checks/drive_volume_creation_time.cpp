#include "../session/session_types.hpp"
#include <bit>
// Recovered behavior summary:
//   Input: A drive device handle, volume-control output, and file-information fallback.
//   Gate: Uses the first control-output word when available; otherwise uses volume-handle
//         CreationTime, with no zero-time rejection.
//   Output: Returns the decoded volume creation time and a strict-after-baseline detection result.
//   Failure: Open/control/info failures follow the recovered fallback/error branches; FILETIME
//            arithmetic intentionally wraps.

namespace ocean::reconstructed::drive_volume_creation_time {
struct Time {
    std::uint64_t wall,ext,location;
};
struct Result {Time value;bool error;};
struct HandleResult {
    std::uint64_t handle;
    bool error;
};
struct ControlResult {
    std::uint64_t first_output_word;
    bool error;
};
struct FileInfoResult {
    std::uint64_t creation_filetime;
    bool error;
};
struct Contracts {
    virtual bool original_utf16_conversion_fails(const ByteString&)=0;
    virtual HandleResult original_create_file_w(const ByteString&,std::uint32_t access,
        std::uint32_t share,std::uint32_t disposition,std::uint32_t flags)=0;
    virtual ControlResult original_device_io_control(std::uint64_t,std::uint32_t code,
        std::uint32_t zero_initialized_output_bytes)=0;
    virtual FileInfoResult original_get_file_information_by_handle(std::uint64_t)=0;
    virtual void original_close_handle_ignoring_error(std::uint64_t)=0;
    virtual std::uint64_t original_local_location()=0;
    virtual bool original_after(Time,Time)=0;
};
Time convert_filetime(Contracts& runtime,std::uint64_t filetime) {
    // Original signed nanosecond overflow is deliberately retained. FILETIME=0
    // in the fallback is not rejected and can wrap to a surprising future time.
    const auto nanoseconds=std::bit_cast<std::int64_t>(filetime*100u+0x5e6684f4b3960000ULL);
    auto seconds=nanoseconds/1000000000;
    auto remainder=nanoseconds%1000000000;
    if(remainder<0) {remainder+=1000000000;--seconds;}
    return {static_cast<std::uint64_t>(remainder),
            static_cast<std::uint64_t>(seconds+62135596800LL),runtime.original_local_location()};
}
Result get(Contracts& runtime,ByteString drive) { //fQv@1298960
    if(!drive.empty() && drive.back()=='\\') drive.pop_back();
    const ByteString device="\\\\.\\"+drive;
    HandleResult volume{};
    bool volume_open=false;
    if(!runtime.original_utf16_conversion_fails(device)) {
        volume=runtime.original_create_file_w(device,0x80000000,3,3,0x02000080);
        if(!volume.error) {
            volume_open=true;
            const auto control=runtime.original_device_io_control(volume.handle,0x900f4,56);
            // Input pointer/size zero; byte-count output is ignored. First output
            // uint64 only, not a parsed whole-volume structure. No zero timestamp rejection below.
            if(!control.error && control.first_output_word!=0) {
                const auto time=convert_filetime(runtime,control.first_output_word);
                runtime.original_close_handle_ignoring_error(volume.handle);
                return {time,false};
            }
        }
    }
    const auto finish_volume=[&] {
        if(volume_open) runtime.original_close_handle_ignoring_error(volume.handle);
    };
    const auto root=device+"\\";
    if(runtime.original_utf16_conversion_fails(root)) {finish_volume();return {{},true};}
    const auto directory=runtime.original_create_file_w(root,0x80000000,7,3,0x02000000);
    if(directory.error) {finish_volume();return {{},true};}
    const auto info=runtime.original_get_file_information_by_handle(directory.handle);
    // Native buffer is52bytes zero initialized. CreationTime begins at +4.
    const auto result=info.error ? Result{{},true} : Result{convert_filetime(runtime,info.creation_filetime),false};
    runtime.original_close_handle_ignoring_error(directory.handle);
    finish_volume(); //reverse defer order; close errors ignored
    return result;
}
Result check_since_baseline(Contracts& runtime,const ByteString& drive,Time baseline) { //ovAW@1299040
    const auto timestamp=get(runtime,drive);
    if(timestamp.error || !runtime.original_after(timestamp.value,baseline)) return {{},true};
    return timestamp;
}
// Captured binding identities:kernel32 CreateFileW,DeviceIoControl,
// GetFileInformationByHandle,CloseHandle.10 original provider fixtures returned
// under explicit synthetic native results. No API/source invocation.
}
