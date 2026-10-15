#include "../session/session_types.hpp"
#include <vector>
#include <cstddef>
#include <cstdint>
namespace ocean::reconstructed::native_unload_trace {
// Recovered: query RtlGetUnloadEventTraceEx metadata, copy the target process's
// unload ring, format entries into delimiter-separated text, and split it for Go.
// Missing exports/open/read/allocation failures return no rows.
using Address = std::uint64_t;
struct Entry {
    Address base = 0, image_size = 0;
    std::uint32_t sequence = 0, pe_timestamp = 0, checksum = 0;
    char16_t image_name[32]{};
};
struct Addresses {
    Address entry_size = 0, entry_count = 0, trace_pointer = 0;
};
struct Contracts {
    virtual Address load_library_a(const char *name) = 0;
    virtual Address get_proc_address(Address, const char *name) = 0;
    virtual Addresses call_rtl_get_unload_event_trace_ex(Address function) = 0;
    virtual Address open_process(std::uint32_t access, bool inherit, std::uint32_t pid) = 0;
    virtual bool read_process_memory(Address process, Address from, void *to, std::uint64_t bytes,
                                     Address returned_bytes_pointer) = 0;
    virtual void *malloc(std::uint64_t bytes) = 0;
    virtual void free(void *) = 0;
    virtual void close_handle_ignoring_result(Address) = 0;
    virtual void print_missing_rtl_export_error() = 0;
    virtual std::int32_t format_row(char *output, std::uint64_t capacity, const char16_t *name,
                                    std::uint32_t image_size, std::uint32_t pe_timestamp,
                                    std::uint32_t checksum, const char *separator) = 0;
    virtual std::uint64_t strlen(const char *) = 0;
    virtual ByteString go_copy_c_string(const char *) = 0;
};
struct Globals {
    Address rtl_unload_export = 0;
}; // captured native global7789dc0, overwritten each call
char *read_native(Contracts &rt, Globals &globals,
                  std::uint32_t pid) { // native20aacc0, cgo wrapper20ab190
    const auto ntdll = rt.load_library_a("ntdll.dll");
    globals.rtl_unload_export = rt.get_proc_address(ntdll, "RtlGetUnloadEventTraceEx");
    if (globals.rtl_unload_export == 0) {
        rt.print_missing_rtl_export_error();
        return nullptr;
    }
    const auto process =
        rt.open_process(0x10, false, pid); // PROCESS_VM_READ; handle failure NOT checked
    std::uint32_t entry_size = 0, count = 0;
    Address remote_trace = 0;
    const auto locations = rt.call_rtl_get_unload_event_trace_ex(globals.rtl_unload_export);
    rt.read_process_memory(process, locations.entry_size, &entry_size, 4, 0);
    rt.read_process_memory(process, locations.entry_count, &count, 4, 0);
    rt.read_process_memory(process, locations.trace_pointer, &remote_trace, 8, 0);
    if (remote_trace == 0)
        return nullptr; // process handle leaked on this early exit
    if (count > 16384)
        count = 16384;
    const std::uint32_t bytes =
        entry_size * count; // original32-bit multiplication, wraps; no entry-size validation
    auto *copied = static_cast<unsigned char *>(rt.malloc(bytes));
    if (copied == nullptr)
        return nullptr; // process handle leaked here too
    rt.read_process_memory(process, remote_trace, copied, bytes,
                           0); // all read statuses/lengths ignored
    std::uint64_t length = 0;
    auto *at = copied;
    for (std::uint32_t index = 0; index < count; ++index, at += entry_size) {
        const auto *entry = reinterpret_cast<const Entry *>(at);
        if (entry->base == 0)
            break; // stop at first unused entry, not skip
        const auto n =
            rt.format_row(nullptr, 0, entry->image_name, std::uint32_t(entry->image_size),
                          entry->pe_timestamp, entry->checksum, index < count - 1 ? "\n" : "");
        length += std::uint64_t(std::int64_t(n)); // negative formatter result wraps into length
    }
    auto *output = static_cast<char *>(rt.malloc(length + 1));
    if (output == nullptr) {
        rt.free(copied);
        rt.close_handle_ignoring_result(process);
        return nullptr;
    }
    output[0] = 0;
    at = copied;
    for (std::uint32_t index = 0; index < count; ++index, at += entry_size) {
        const auto *entry = reinterpret_cast<const Entry *>(at);
        if (entry->base == 0)
            break;
        const auto used = rt.strlen(output);
        rt.format_row(output + used, length - used, entry->image_name,
                      std::uint32_t(entry->image_size), entry->pe_timestamp, entry->checksum,
                      index < count - 1 ? "\n" : "");
        // Capacity excludes the extra allocated terminator byte. With standard
        // snprintf semantics this clips the final character when last entry is used.
    }
    rt.free(copied);
    rt.close_handle_ignoring_result(process);
    return output;
    // Native format is "%ls:::%u:::%u:::%u%s": name, LOW32 image size,
    // PE timestamp and checksum. Sequence/actual base are not formatted. No
    // FreeLibrary call. Failed/short remote reads can leave C heap data undefined;
    // this reconstruction does not invent a zero-filled buffer or success gate.
}
std::vector<ByteString> go_bridge(Contracts &rt, Globals &globals,
                                  std::uint32_t pid) { // JdlQGviD7W@6d98c0, qZU3miCaVk@6d9940
    const auto *native = read_native(rt, globals, pid);
    if (native == nullptr)
        return {};
    const auto text = rt.go_copy_c_string(native); // raw current-CRT bytes, no UTF8 validation
    std::vector<ByteString> rows;
    std::size_t begin = 0;
    for (;;) {
        const auto end = text.find('\n', begin);
        auto row = text.substr(begin, end == ByteString::npos ? end : end - begin);
        if (!row.empty())
            rows.push_back(std::move(row)); // duplicates, CR and spaces retained
        if (end == ByteString::npos)
            break;
        begin = end + 1;
    }
    return rows; // the original Go wrapper does NOT free the native returned CString
}
// Native14 controlled routes, original Go bridge8 routes. Native body control/
// data instructions interpreted with synthetic Win32/CRT providers, ASCII names,
// poisoned malloc buffers and explicit normalization of six protected-import
// callsites. Protected thunk implementation/API-role resolution is NOT proved:
// LoadLibrary/OpenProcess/ReadProcessMemory roles follow caller ABI+dataflow,
// while the Rtl export string/entry fields are directly recovered. Keep this
// limitation with the source; it is not a claim of a fully unpacked native binary.
// Source stays guest-only, never compiled or executed.
} // namespace ocean::reconstructed::native_unload_trace
