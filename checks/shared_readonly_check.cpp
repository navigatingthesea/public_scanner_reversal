#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: Two fixed paths: NVIDIA nvAppTimestamps and the current user PSReadLine
//          ConsoleHost_History.txt.
//   Gate: Stats each path twice and matches when FileMode owner-write bit 0x80 is absent.
//   Output: Emits a ReadOnly console/debug row for each qualifying path.
//   Failure: Either Stat failure suppresses that path; this is a mode-bit test, not a Windows ACL
//            or drive-access check.

namespace ocean::reconstructed::shared_readonly {

using Handle = std::uint64_t;

template<class T>
struct Read {
    T value{};
    bool error = false;
};

struct Contracts {
    virtual Read<Handle> stat_following_links(const ByteString&) = 0;
    virtual std::uint32_t file_info_mode(Handle) = 0;
    virtual ByteString go_windows_filepath_join(
        const std::vector<ByteString>&) = 0;
    virtual void recover_silently(const std::function<void()>&) = 0;
    virtual void print_text(const ByteString&) = 0;
    virtual void append_debug_readonly(const ByteString& path) = 0;
};

Read<bool> owner_write_bit_missing(
    Contracts& runtime,
    const ByteString& path) { // e_XaFv5 @ 0x12af4a0
    const auto file_info = runtime.stat_following_links(path);
    if (file_info.error) {
        return {false, true};
    }
    return {(runtime.file_info_mode(file_info.value) & 0x80) == 0, false};
}

void check(Contracts& runtime,
           const ByteString& global_username) { // HuwaqX7 @ 0x12af520
    runtime.recover_silently([&] {
        const ByteString nvidia =
            "C:\\ProgramData\\NVIDIA Corporation\\Drs\\nvAppTimestamps";
        const auto check_path = [&](const ByteString& path,
                                    const ByteString& message) {
            if (runtime.stat_following_links(path).error) {
                return; // first Stat; returned FileInfo is unused
            }
            const auto read_only = owner_write_bit_missing(runtime, path);
            if (read_only.error || !read_only.value) {
                return;
            }
            runtime.print_text(message);
            runtime.append_debug_readonly(path);
        };

        check_path(
            nvidia,
            "Generic Bypass Method (nvAppTimestamps Read-only):::Boot instance:::Modified nvApptimestamps file to read-only permissions");
        const auto history = runtime.go_windows_filepath_join({
            "C:", "Users", global_username, "AppData", "Roaming", "Microsoft",
            "Windows", "PowerShell", "PSReadLine", "ConsoleHost_History.txt",
        });
        check_path(
            history,
            "Generic Bypass Method (psHistory Read-only):::Boot instance:::Modified ConsoleHost_History file to read-only permissions");
    });

    // Debug row: ["Detect", "ReadOnly", path]. There is no warning-slice or
    // timestamp test. "C:" is a drive-relative join component, and the username
    // is the single global value at RVA 0x572b7f0. FileMode 0200 is a Go mode-bit
    // test; it does not inspect Windows ACLs or file contents.
}

// Fourteen original routes include eight mode values and the exact ten path
// components. Stat, FileInfo, and filepath.Join remain provider contracts.

}  // namespace ocean::reconstructed::shared_readonly
