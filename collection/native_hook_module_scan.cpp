#include "../session/session_types.hpp"
namespace ocean::reconstructed::native_hook_module_scan {
// Recovered: for each eligible module, read the local image and full remote image,
// locate the local .text section, compare its bytes with remote memory, and append
// formatted hook rows. Missing/invalid data usually yields no rows and scanning continues.
using Address = std::uint64_t;
struct Module {
    Address base = 0;
    std::uint32_t image_size = 0;
    ByteString path, name;
};
struct Buffer {
    Address data = 0;
    std::size_t size = 0;
};
struct Text {
    std::uint32_t virtual_size = 0, rva = 0, raw_offset = 0;
};
struct Contracts {
    virtual Buffer read_entire_local_file_binary(const ByteString &) = 0;
    virtual void release_local_file_buffer(Buffer) = 0;
    virtual std::uint16_t unsafe_u16(Address) = 0;
    virtual std::uint32_t unsafe_u32(Address) = 0;
    virtual ByteString unsafe_cstring(Address) = 0;
    virtual Address virtual_alloc(std::uint32_t size, std::uint32_t type,
                                  std::uint32_t protection) = 0;
    virtual void read_remote_ignoring_status(Address base, Address destination,
                                             std::uint32_t size) = 0;
    virtual void virtual_free_ignoring_status(Address, std::uint32_t size, std::uint32_t type) = 0;
    virtual std::uint32_t compare_text(const Module &, Buffer file, Address remote_copy,
                                       const Text &, std::vector<ByteString> &hooks) = 0;
};
bool eligible(const Module &module) {
    if (module.base == 0 || module.name.find(".dll") == ByteString::npos)
        return false;
    for (const ByteString excluded : {"d3dcompiler", "D3DCOMPILER", "dbghelp", "stub.dll", "XAudio",
                                      "gameoverlayrenderer64.dll"})
        if (module.name.find(excluded) != ByteString::npos)
            return false;
    return true; // case-sensitive SUBSTRINGS; .dll need not be at the end
}
Text find_text(Contracts &rt, Address file) {
    Text text;
    if (rt.unsafe_u16(file) != 0x5a4d)
        return text;
    const auto pe = file + static_cast<std::int32_t>(rt.unsafe_u32(file + 60));
    if (rt.unsafe_u32(pe) != 0x4550)
        return text;
    auto sections = rt.unsafe_u16(pe + 6);
    auto section = pe + 24 + rt.unsafe_u16(pe + 20);
    for (std::uint32_t k = 0; k < sections; ++k, section += 40)
        if (rt.unsafe_cstring(section) == ".text")
            return {rt.unsafe_u32(section + 8), rt.unsafe_u32(section + 12),
                    rt.unsafe_u32(section + 20)};
    return text;
    // strcmp against section-name CString; no file-size/header/section bounds guard,
    // Machine or optional-header magic test. Uses VirtualSize, not SizeOfRawData.
}
void scan_modules(Contracts &rt, const std::vector<Module> &modules,
                  std::vector<ByteString> &hooks) { // 33cc420..33cca51
    hooks.reserve(std::max<std::size_t>(hooks.capacity(), 256));
    for (const auto &module : modules) {
        if (!eligible(module))
            continue;
        const auto disk = rt.read_entire_local_file_binary(module.path);
        if (disk.data == 0)
            continue; // file helper boolean ignored; data pointer is gate
        const auto text = find_text(rt, disk.data);
        const auto copy = rt.virtual_alloc(module.image_size, 0x3000, 4);
        rt.read_remote_ignoring_status(module.base, copy, module.image_size);
        rt.compare_text(module, disk, copy, text, hooks); // numeric return count discarded
        rt.virtual_free_ignoring_status(copy, 0, 0x8000);
        rt.release_local_file_buffer(disk);
    }
    // A missing/invalid .text still allocates/reads FULL remote image before the
    // zero-size comparator returns. Null allocation or failed copy does NOT skip
    // the comparator. No extra safety guard has been inserted into review source.
}
// The file helper33ca8b0 opens binary ifstream, reads its whole stream into a
// vector, closes and destroys stream. It returns open-state (flags&5)==0;
// post-open read/close failures do not change that saved boolean. Caller ignores
// the boolean. Partial reads/allocated empty vectors follow native stdlib behavior.
// The ordinary C++ allocation/string/file-stream runtime is an explicit contract;
// buffer cleanup on thrown exceptions is governed by its native unwind metadata.
// Recovered: 24 dispatcher routes cover 15 name/case variants and nine
// header/read/allocation
// failures. Native I/O and comparator synthetic, no files/processes collected.
// Protected read thunk78dd1ca returns at call+6, revealing real64bit context move
// hidden in overlapping linear-disassembly instructions. No source compile/run.
} // namespace ocean::reconstructed::native_hook_module_scan
