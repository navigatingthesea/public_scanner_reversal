#include "../session/session_types.hpp"
namespace ocean::reconstructed::native_hook_names {
// Recovered: label a source RVA by exact PE export name when available, otherwise
// by hexadecimal RVA; label a destination by the first containing module plus
// offset, otherwise as a raw pointer. Invalid export metadata yields an empty name.
using Address = std::uint64_t;
struct Module {
    Address base = 0;
    std::uint32_t image_size = 0;
    ByteString path, name;
}; // native64byte record
struct Memory {
    virtual std::uint16_t unsafe_u16(Address) = 0;
    virtual std::uint32_t unsafe_u32(Address) = 0;
    virtual ByteString unsafe_cstring(Address) = 0;
    virtual ByteString sprintf_hex_u32(std::uint32_t) = 0; //"0x%x"
    virtual ByteString sprintf_hex_pointer(Address) = 0;   //"0x%p"
};
ByteString export_name_or_rva(Memory &rt, Address image, std::uint32_t rva) { // 33ca6c0..33ca8a9
    if (rt.unsafe_u16(image) != 0x5a4d)
        return {};
    const auto pe = image + static_cast<std::int32_t>(rt.unsafe_u32(image + 60));
    if (rt.unsafe_u32(pe) != 0x4550)
        return {};
    const auto exports = rt.unsafe_u32(pe + 0x88);
    if (exports == 0)
        return {};
    const auto directory = image + exports;
    const auto count = rt.unsafe_u32(directory + 24);
    const auto functions = image + rt.unsafe_u32(directory + 28);
    const auto names = image + rt.unsafe_u32(directory + 32);
    const auto ordinals = image + rt.unsafe_u32(directory + 36);
    for (std::uint64_t k = 0; k < count; ++k) {
        const auto name = image + rt.unsafe_u32(names + 4 * k);
        if (name == 0 || functions == 0 || ordinals == 0)
            continue;
        const auto ordinal = rt.unsafe_u16(ordinals + 2 * k);
        const auto function = rt.unsafe_u32(functions + 4 * ordinal);
        if (function == rva && function != 0)
            return rt.unsafe_cstring(name);
    }
    return rt.sprintf_hex_u32(rva);
    // No nearest-export lookup, ordinal-only export name, forwarder resolution,
    // PE32 optional-header detection, export-table/name/ordinal/buffer bounds checks.
    // Invalid MZ/PE or absent export directory returns EMPTY, not a hex fallback.
}
ByteString destination(Memory &rt, const std::vector<Module> &modules,
                       Address address) { // 33cac00..33cae53
    for (const auto &module : modules)
        if (module.base <= address && address < module.base + std::uint64_t(module.image_size))
            return module.name + "+" + rt.sprintf_hex_u32(std::uint32_t(address - module.base));
    return rt.sprintf_hex_pointer(address);
    // First containing module wins; end exclusive; wrapping end not checked.
    // No symbol lookup here. Path not included in this label, name case preserved.
}
// Seventeen original helper routes: exact/nonexact/invalid export PE cases and
// module boundaries/overlap. CRT pointer formatting remains an explicit contract.
// String ownership/allocation and exception unwinding use standard C++ semantics.
// Guest-only review source, never compiled or executed.
} // namespace ocean::reconstructed::native_hook_names
