#include "../../session/session_types.hpp"
#include <array>
#include <algorithm>
namespace ocean::reconstructed::minecraft_native_java_review {
// Recovered: three independent runtime checks are represented here: loaded JVM
// debugging/instrumentation modules, Weave byte strings in private committed
// memory, and a thread description containing "attach listener".
//
// Interpretation: these checks look for active Java instrumentation or loader
// traces. They are not part of HotSpot class metadata parsing.
//
// Unresolved: Windows API bindings and Go runtime defer/panic behavior remain
// explicit contracts; this review source cannot access a process by itself.
struct ModuleEnumeration {
    bool success = false;
    std::uint32_t bytes_needed = 0;
    std::vector<NativeHandle> handles;
};
struct ModulePath {
    GoUint native_return = 0;
    ByteString converted_utf16_buffer;
};
struct ThreadEntry {
    std::uint32_t id, owner_pid;
};
struct ThreadDescription {
    GoUint native_return = 0;
    std::uint64_t allocated_pointer = 0;
};
struct MemoryRegion {
    GoUint base, size;
    std::uint32_t state, protection, type;
};
struct VirtualMemoryQuery {
    GoUint native_return = 0;
    MemoryRegion value{};
};
struct MemoryRead {
    bool success = false;
    GoUint bytes_read = 0;
    std::vector<std::uint8_t> bytes;
};
struct NativeJavaContracts : TextContracts {
    virtual Result<NativeHandle> original_open_process(std::uint32_t access, bool inherit,
                                                       std::int32_t pid) = 0;
    virtual void original_register_deferred_close(NativeHandle) = 0;
    virtual void original_close(NativeHandle) = 0;
    virtual ModuleEnumeration original_k32_enum_modules(NativeHandle, std::uint32_t capacity_bytes,
                                                        std::uint32_t mode) = 0;
    virtual ModulePath original_k32_module_path(NativeHandle, NativeHandle module,
                                                std::uint32_t utf16_capacity) = 0;
    virtual Result<NativeHandle> original_snapshot(std::uint32_t flags, std::uint32_t pid) = 0;
    virtual Result<ThreadEntry> original_thread_first(NativeHandle, std::uint32_t record_bytes) = 0;
    virtual Result<ThreadEntry> original_thread_next(NativeHandle, std::uint32_t record_bytes) = 0;
    virtual Result<NativeHandle> original_open_thread(std::uint32_t, bool, std::uint32_t) = 0;
    virtual ThreadDescription original_get_thread_description(NativeHandle) = 0;
    virtual ByteString original_utf16_pointer_to_string(std::uint64_t) = 0;
    virtual void original_local_free(std::uint64_t) = 0;
    virtual VirtualMemoryQuery original_virtual_query(NativeHandle, GoUint address,
                                                      std::uint32_t structure_bytes) = 0;
    virtual MemoryRead original_read_process_memory(NativeHandle, GoUint address,
                                                    GoUint length) = 0;
    virtual const std::vector<ByteString> &current_weave_memory_needles() = 0; // captured56635b0
    virtual void original_panic_read_count_out_of_bounds() = 0;
    virtual void append_warning(const ByteString &) = 0; // 572e7a0 -> WARNINGS
    virtual void
    append_debug_strings(const std::vector<ByteString> &) = 0; // 572e8e0 -> DEBUG_DETECTIONS
    virtual void append_debug_with_int32_pid(const ByteString &level, const ByteString &label,
                                             std::int32_t) = 0;
    virtual void original_diagnostic_log_contract(const ByteString &) = 0;
};
std::vector<ByteString> captured_memory_needles() {
    return {"\\.weave\\", "/.weave/", "weave-loader", "net/weavemc", "net.weavemc", "weavemc"};
}
// Recovered ixdmtXAh_@1c0bd60: K32EnumProcessModulesEx mode 3 first queries the
// required byte count with no buffer. The uint32 count divided by eight must be
// 1..8192. The second call uses and iterates the initial count even if it changes.
// Original slice is zero initialized; partial writes stay zero module handles.
bool check_loaded_modules(NativeJavaContracts &r, NativeHandle process) {
    const auto first = r.original_k32_enum_modules(process, 0, 3);
    if (!first.success || first.bytes_needed == 0)
        return false;
    const auto count = first.bytes_needed >> 3;
    if (count == 0 || count > 8192)
        return false;
    const auto second = r.original_k32_enum_modules(process, first.bytes_needed, 3);
    if (!second.success)
        return false;
    bool instrument = false, attach = false, jdwp = false;
    for (std::uint32_t k = 0; k < count; ++k) {
        const auto path = r.original_k32_module_path(process, second.handles[k], 260);
        if (path.native_return == 0)
            continue;
        const auto lower = r.to_lower(path.converted_utf16_buffer);
        instrument = instrument || lower.find("\\instrument.dll") != ByteString::npos;
        attach = attach || lower.find("\\attach.dll") != ByteString::npos;
        jdwp = jdwp || lower.find("\\jdwp.dll") != ByteString::npos;
        // Byte substrings, not extension/base equality: instrument.dll.extra matches.
        // No forwardslash normalization. No hashes/content/signature check here.
    }
    if (jdwp) {
        r.append_warning("Remote Debugging:::Loaded Module:::.:::Debug module:::Module: "
                         "jdwp.dll:::State: active in game process");
        r.append_debug_strings({"Warning", "JVMJDWP"});
    }
    if (attach) {
        r.append_warning("Injection Tool:::Loaded Module:::.:::Attach module:::Module: "
                         "attach.dll:::State: loaded in game process");
        r.append_debug_strings({"Warning", "JVMAttachDLL"});
    }
    return instrument;
}
// Recovered f39V5X2i@1c0e940: search lowercased extracted runs longer than five
// bytes for any captured Weave needle. The original sets a shared flag under mutex;
// readable local bool represents the uncontended core, not Go mutex internals.
bool suspicious_memory_run(NativeJavaContracts &r, const ByteString &run) {
    if (run.size() <= 5)
        return false;
    const auto lower = r.to_lower(run);
    for (const auto &needle : r.current_weave_memory_needles())
        if (lower.find(needle) != ByteString::npos)
            return true;
    return false;
}
// Recovered zkgWhSg@1c0ea60: scan printable ASCII runs, then aligned UTF-16LE
// units whose high byte is zero and low byte is 0x20..0x7e. Runs reset on a
// nonprintable unit. There is no cross-chunk carry or odd-alignment UTF-16 pass.
bool scan_one_chunk(NativeJavaContracts &r, const std::vector<std::uint8_t> &bytes, std::size_t n) {
    ByteString run;
    for (std::size_t i = 0; i < n; ++i) {
        if (bytes[i] >= 0x20 && bytes[i] <= 0x7e)
            run.push_back(static_cast<char>(bytes[i]));
        else {
            if (suspicious_memory_run(r, run))
                return true;
            run.clear();
        }
    }
    if (suspicious_memory_run(r, run))
        return true;
    run.clear();
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        if (bytes[i + 1] == 0 && bytes[i] >= 0x20 && bytes[i] <= 0x7e)
            run.push_back(static_cast<char>(bytes[i]));
        else {
            if (suspicious_memory_run(r, run))
                return true;
            run.clear();
        }
    }
    return suspicious_memory_run(r, run);
}
bool scan_weave_memory(NativeJavaContracts &r, NativeHandle process) {
    GoUint address = 0, total_read = 0;
    while (true) {
        const auto query = r.original_virtual_query(process, address, 48);
        if (query.native_return == 0 || query.value.size == 0 || total_read > 0x2fffffff)
            break;
        const auto region = query.value;
        const auto protect = region.protection & 0xff;
        const bool allowed = region.state == 0x1000 && region.type == 0x20000 &&
                             region.size <= 0x6000000 && !(region.protection & 0x100) &&
                             !(region.protection & 1) &&
                             (protect == 2 || protect == 4 || protect == 0x20 || protect == 0x40);
        if (allowed) {
            for (GoUint offset = 0; offset < region.size; offset += 65536) {
                const auto read = r.original_read_process_memory(
                    process, region.base + offset, std::min<GoUint>(65536, region.size - offset));
                if (!read.success || read.bytes_read == 0)
                    break;
                if (read.bytes_read > 65536) {
                    r.original_panic_read_count_out_of_bounds();
                    return false;
                }
                total_read += read.bytes_read;
                if (scan_one_chunk(r, read.bytes, static_cast<std::size_t>(read.bytes_read)))
                    return true;
            }
        }
        address = region.base + region.size; // Go unsigned addition/wrap preserved.
    }
    return false;
}
// Recovered pxVRPMrL@1c0e660: create a flag-4 thread snapshot for PID 0, use a
// 28-byte THREADENTRY32, filter by owner PID, and OpenThread with access 0x800.
// The machine code accepts GetThreadDescription only when its uint64 return is
// exactly 1, rather than applying SUCCEEDED(). Preserve that apparent bug.
bool has_attach_listener_thread(NativeJavaContracts &r, std::int32_t pid) {
    const auto snapshot = r.original_snapshot(4, 0);
    if (snapshot.error.present())
        return false;
    r.original_register_deferred_close(snapshot.value);
    for (auto entry = r.original_thread_first(snapshot.value, 28); !entry.error.present();
         entry = r.original_thread_next(snapshot.value, 28)) {
        if (entry.value.owner_pid != static_cast<std::uint32_t>(pid))
            continue;
        const auto thread = r.original_open_thread(0x800, false, entry.value.id);
        if (thread.error.present())
            continue;
        const auto description = r.original_get_thread_description(thread.value);
        if (description.native_return == 1 && description.allocated_pointer != 0) {
            const auto text = r.original_utf16_pointer_to_string(description.allocated_pointer);
            r.original_local_free(description.allocated_pointer);
            if (r.to_lower(text).find("attach listener") != ByteString::npos) {
                r.original_close(thread.value);
                return true;
            }
        }
        // When native return!=1, original body does NOT free a nonnull result.
        // This likely leaks a successful result buffer; reconstructed source retains
        // original behavior. The benign diagnostic fixture freed its OWN buffer.
        r.original_close(thread.value);
    }
    return false;
}
// Recovered qctTAL5dYbB@1c0f3a0: an upstream worker selects only exact java.exe
// or javaw.exe names. The original_name argument does not affect this output.
// expected_agent is true for the recovered environment or command-line agent markers;
// only low byte meaningful. It suppresses later instrument/thread detection,
// after loaded-module side warnings and Weave memory warning have run.
void inspect_java_process(NativeJavaContracts &r, const ByteString &original_name, std::int32_t pid,
                          bool expected_agent) {
    const auto process = r.original_open_process(0x410, false, pid);
    if (process.error.present())
        return;
    r.original_register_deferred_close(process.value);
    const auto instrument = check_loaded_modules(r, process.value);
    if (scan_weave_memory(r, process.value)) {
        r.append_warning("Weave Cheat Loader:::In Memory:::.:::Memory scan:::Weave traces found in "
                         "the running game's memory");
        r.append_debug_strings({"Warning", "WeaveMemory"});
    }
    if (expected_agent)
        return;
    if (has_attach_listener_thread(r, pid)) {
        r.original_diagnostic_log_contract("original qct.func3; deeper logger binding retained");
        r.append_debug_with_int32_pid("Detect", "JVMAttachListener", pid);
    } else if (instrument) {
        r.original_diagnostic_log_contract("original qct.func5; deeper logger binding retained");
        r.append_debug_with_int32_pid("Detect", "JVMInstrumentInjected", pid);
    }
}
} // namespace ocean::reconstructed::minecraft_native_java_review
