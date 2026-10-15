#include "../session/session_types.hpp"
#include <array>
namespace ocean::reconstructed::native_hook_modules {
// Recovered: enumerate Toolhelp modules for one PID, read each remote PE header,
// and output base, SizeOfImage, ANSI path, and name in enumeration order. Header
// read failures still append a zero-size module; snapshot creation failure is empty.
using Handle = std::uint64_t;
using Address = std::uint64_t;
struct Entry {
    std::uint32_t dw_size = 568;
    Address base = 0;
    ByteString ansi_name, ansi_path;
};
struct Module {
    Address base = 0;
    std::uint32_t image_size = 0;
    ByteString ansi_path, ansi_name;
};
struct Contracts {
    virtual Handle create_module_snapshot(std::uint32_t flags, std::uint32_t pid) = 0;
    virtual bool module_first_a(Handle, Entry &) = 0;
    virtual bool module_next_a(Handle, Entry &) = 0;
    virtual void close_handle_ignoring_result(Handle) = 0;
    virtual bool read_remote(Handle process, Address, Bytes &zero_initialized_buffer,
                             std::uint32_t count) = 0;
    virtual std::uint32_t unsafe_u32(const Bytes &, std::size_t offset) = 0;
};
std::vector<Module> enumerate(Contracts &rt, Handle process,
                              std::uint32_t pid) { // 33ca150..33ca527
    std::vector<Module> modules;
    Entry entry;
    auto snapshot = rt.create_module_snapshot(8, pid); // TH32CS_SNAPMODULE, no SNAPMODULE32 bit
    if (snapshot == 0 || snapshot == UINT64_MAX)
        return modules;
    if (rt.module_first_a(snapshot, entry))
        do {
            Bytes header(265, 0);
            Bytes dos(64, 0);
            const bool dos_read = rt.read_remote(process, entry.base, dos, 64);
            const auto pe_offset = dos_read ? static_cast<std::int32_t>(rt.unsafe_u32(dos, 60)) : 0;
            Bytes nt(264, 0);
            if (rt.read_remote(process, entry.base + pe_offset, nt, 264)) {
                std::copy(nt.begin(), nt.end(), header.begin());
                header[264] = 1; // unused marker adjacent to copy
            }
            // Failed NT read leaves zeroed265bytes. No MZ/PE/header-range check here.
            const auto image_size = rt.unsafe_u32(header, 0x50);
            modules.push_back({entry.base, image_size, entry.ansi_path, entry.ansi_name});
        } while (rt.module_next_a(snapshot, entry));
    rt.close_handle_ignoring_result(snapshot);
    return modules;
    // Size comes from NT optional-header SizeOfImage, NOT MODULEENTRY32.modBaseSize.
    // A failed first read still issues second at module.base+0. Signed e_lfanew,
    // including negative values, is added without a validity guard. A failed second
    // read still appends a module with size zero. No base/extension filter is applied here.
}
// Interpretation: Toolhelp API roles follow the native ABI, snapshot flag 8,
// dwSize 568, ANSI
// record fields and loop behavior. Captured import targets/return-stack behavior
// are traced; exact export-name binding to the original OS DLL is not available.
// Protected read calls have a leading pushed register consumed by their thunk;
// normalized instruction fixtures preserve logical caller stack and returned PC.
// Eleven original routes including both read failures, mismatched module/header
// sizes, invalid PE signature, signed offset and multi-module enumeration.
// Standard vector/string allocation cleanup explicit; the snapshot is explicitly
// closed after enumeration, so a C++ exception before close can leak that handle.
// No real snapshot/process/native calls; guest-only source, never compiled/run.
} // namespace ocean::reconstructed::native_hook_modules
