#include "../session/session_types.hpp"
#include <vector>
// Recovered behavior summary:
//   Input: GetLogicalDriveStringsW, GetDriveTypeW, and GetVolumeInformationW provider results.
//   Gate: Fixed and network drives are retained; removable and CD-ROM volume-query failures are
//         skipped according to the recovered branches.
//   Output: Returns drive path, filesystem bytes, and ro/rw access records.
//   Failure: The original fixed-size buffers, ignored UTF-16 error, and partial-result error
//            behavior are preserved.

namespace ocean::reconstructed::shared_drive_enumerator {
struct Error {std::uint64_t type,data;};
struct NativeResult {
    std::uint64_t value;
    Error error;
};
struct Drive {
    ByteString name,path,filesystem,access;
}; //64 bytes:four GoStrings
struct Result {
    std::vector<Drive> drives;
    Error error;
};
struct VolumeResult {
    NativeResult call;
    std::uint32_t flags;
    std::vector<std::uint8_t> filesystem_bytes;
};
struct LogicalResult {
    NativeResult call;
    std::vector<std::uint8_t> bytes;
};
struct Contracts {
    // Original GetLogicalDriveStringsW uses capacity254 but allocation254 BYTES,
    // and scans ALL254 bytes regardless returned character count. Retain call
    // shape for review; synthetic providers here cannot write outside a buffer.
    virtual LogicalResult original_logical_drive_strings(std::uint32_t capacity,
        std::uint32_t allocation_bytes)=0;
    // UTF16 converter error is ignored by this caller, unlike removable helper152.
    virtual NativeResult original_get_drive_type_ignoring_conversion_error(const ByteString&)=0;
    virtual Error original_get_last_error()=0;
    // Original root letter+":/". Volume name/filesystem buffers each256 BYTES,
    // API capacities each256 characters. Serial/max-component outputs discarded.
    virtual VolumeResult original_volume_information_ignoring_conversion_error(
        const ByteString& root,std::uint32_t name_capacity,std::uint32_t filesystem_capacity)=0;
};
Result enumerate(Contracts& runtime) { //ACL41A.F9b4zvuy_k@1205880
    Result result;
    const auto logical=runtime.original_logical_drive_strings(254,254);
    if(logical.call.value==0) {result.error=logical.call.error;return result;}
    for(std::size_t at=0;at<254;++at) {
        const auto byte=at<logical.bytes.size() ? logical.bytes[at] : std::uint8_t{0};
        if(byte<'A' || byte>'Z') continue; //raw uppercase byte extraction, no path parser
        const ByteString letter(1,static_cast<char>(byte));
        const auto path=letter+":";
        const auto type=runtime.original_get_drive_type_ignoring_conversion_error(path).value;
        if(type==0) {result.error=runtime.original_get_last_error();return result;}
        if(type<2 || type>5) continue;
        const auto volume=runtime.original_volume_information_ignoring_conversion_error(letter+":/",256,256);
        if(volume.call.value==0) {
            //Removable2/CDROM5 suppress error; fixed3/network4 return partial records.
            if(type==2 || type==5) continue;
            result.error=volume.call.error;return result;
        }
        ByteString access=(volume.flags&0x80000)!=0 ? "ro" : "rw";
        if((volume.flags&16)!=0) access+=".compress";
        ByteString filesystem;
        for(const auto part:volume.filesystem_bytes)
            if(part!=0) filesystem+=static_cast<char>(part);
        // This is bytes.ReplaceAll(NUL,empty), NOT UTF16 decoding. Non-ASCII
        // filesystem name bytes can be mangled. No trimming or stopping at NUL.
        result.drives.push_back({path,path,filesystem,access});
    }
    return result; //duplicates/order preserved; no record for unsuccessful volume query
}
//19 original fixtures returned incltypes0..6, native error interfaces, ro/compress
// flags, duplicates and non-ASCII filesystem bytes. Binding identities captured:
// kernel32 GetLogicalDriveStringsW/GetDriveTypeW/GetVolumeInformationW globals
//572b258/260/268. No API/device/source execution. Review C++ only.
}
