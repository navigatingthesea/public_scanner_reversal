#include "install_time_native_types.hpp"
#include <cstring>
namespace ocean::reconstructed::install_file_time_review {
// Recovered: stat one path and return its Windows creation FILETIME when the
// dynamic Sys value is Win32FileAttributeData; otherwise return ModTime. Stat
// errors propagate, while the recovered FILETIME arithmetic intentionally wraps.
using ByteString = install_registry_time_review::ByteString;
using GoTimeWords = install_registry_time_review::GoTimeWords;
using GoError = install_registry_time_review::GoError;
using TimeResult = install_registry_time_review::TimeResult;
struct NativeFileAttributes { // syscall.Win32FileAttributeData@3766880,36 bytes
    std::uint32_t attributes = 0, creation_low = 0, creation_high = 0, access_low = 0,
                  access_high = 0, write_low = 0, write_high = 0, size_high = 0, size_low = 0;
};
struct FileTimeContracts {
    using Info = std::uint64_t;
    struct SysValue {
        std::uint64_t original_type_rva = 0, data = 0;
    };
    virtual ~FileTimeContracts() = default;
    virtual GoError stat(const ByteString &, Info &) = 0;
    virtual SysValue file_info_sys(Info) = 0;
    virtual NativeFileAttributes read_original_native_file_attributes(SysValue) = 0;
    virtual GoTimeWords file_info_modtime(Info) = 0;
    virtual std::uint64_t original_local_location() = 0;
    virtual std::uint64_t original_utc_location() = 0;
};
// Recovered: syscall.Filetime.Nanoseconds arithmetic wraps at 64 bits, including
// zero ticks. Unlike registry InstallTime, there is no pre-1970 threshold check.
GoTimeWords original_filetime_to_go_time(FileTimeContracts &r, std::uint64_t ticks) {
    const auto raw = ticks * 100ULL + 0x5e6684f4b3960000ULL;
    std::int64_t nanos = 0;
    std::memcpy(&nanos, &raw, sizeof nanos);
    auto seconds = nanos / 1000000000LL;
    auto remainder = nanos % 1000000000LL;
    if (remainder < 0) {
        remainder += 1000000000LL;
        --seconds;
    }
    const auto ext_bits = std::uint64_t(seconds) + 0xe7791f700ULL;
    std::int64_t ext = 0;
    std::memcpy(&ext, &ext_bits, sizeof ext);
    auto location = r.original_local_location();
    if (location == r.original_utc_location())
        location = 0;
    return {std::uint64_t(remainder), ext, location};
}
// Recovered axRr9G5@f2bc80: return layout is three Go time words plus two Go error
// words. The earlier 16-byte HLL return was incomplete; native assembly and seven
// inert fixtures establish all five return registers.
TimeResult file_creation_time(FileTimeContracts &r, const ByteString &path) {
    FileTimeContracts::Info info = 0;
    const auto error = r.stat(path, info);
    if (error)
        return {{}, error};
    const auto sys = r.file_info_sys(info);
    if (sys.original_type_rva == 0x3532300) { // EXACT*Win32FileAttributeData dynamic type
        const auto attributes = r.read_original_native_file_attributes(sys);
        const auto ticks = std::uint64_t(attributes.creation_low) |
                           (std::uint64_t(attributes.creation_high) << 32);
        return {original_filetime_to_go_time(r, ticks), {}};
    }
    return {r.file_info_modtime(info), {}}; // otherSys types useModTime without normalization
}
} // namespace ocean::reconstructed::install_file_time_review
