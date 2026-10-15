#include "../../session/session_types.hpp"
#include <limits>
namespace ocean::reconstructed::minecraft_java_object_class {
// Recovered: decode an object's Klass pointer for compact-header, compressed-
// class-pointer, or plain-pointer JVM layouts. Every source word is read twice
// where the original required a stable remote value.
using Address = std::uint64_t;
struct Decoded {
    Address klass = 0;
    bool valid = false;
};
template <class T> struct Read {
    T value;
    bool error = false;
};
struct Context {
    Address reader = 0, klass_base = 0;
    std::uint32_t klass_shift = 0;
    bool compact_headers = false, compressed_class_pointers = false;
};
struct Contracts {
    virtual bool
    class_layout_available(const Context &) = 0; // eGZePk, java_native_layout_and_names.cpp
    virtual Address required_oop_field_offset(const Context &, const ByteString &) = 0;
    virtual std::uint64_t vm_constant_or_zero(Address reader, const ByteString &) = 0;
    virtual Read<Address> read_pointer(Address reader, Address) = 0;
    virtual Read<std::uint32_t> read32(Address reader, Address) = 0;
};
Decoded narrow_klass(const Context &ctx, std::uint32_t raw) {
    if (raw == 0)
        return {0, true};
    if (ctx.klass_shift > 16 ||
        raw > ((std::numeric_limits<Address>::max() - ctx.klass_base) >> ctx.klass_shift))
        return {};
    return {ctx.klass_base + (Address(raw) << ctx.klass_shift), true};
}
Decoded decode(Contracts &rt, const Context &ctx, Address object) { // t9eW5d@1a89660
    if (object == 0 || !rt.class_layout_available(ctx))
        return {};
    if (ctx.compact_headers) {
        const Address offset = rt.required_oop_field_offset(ctx, "_mark");
        const auto shift = rt.vm_constant_or_zero(ctx.reader, "markWord::klass_shift");
        if (shift < 1 || shift > 63)
            return {};
        const auto first = rt.read_pointer(ctx.reader, object + offset);
        const auto second = rt.read_pointer(ctx.reader, object + offset); // always both reads
        if (first.error || second.error || first.value != second.value || (first.value & 7) > 2)
            return {};
        return narrow_klass(ctx, static_cast<std::uint32_t>(first.value >> shift));
    }
    if (ctx.compressed_class_pointers) {
        const Address offset = rt.required_oop_field_offset(ctx, "_metadata._compressed_klass");
        const auto first = rt.read32(ctx.reader, object + offset);
        const auto second = rt.read32(ctx.reader, object + offset);
        if (first.error || second.error || first.value != second.value)
            return {};
        return narrow_klass(ctx, first.value);
    }
    const Address offset = rt.required_oop_field_offset(ctx, "_metadata._klass");
    const auto first = rt.read_pointer(ctx.reader, object + offset);
    const auto second = rt.read_pointer(ctx.reader, object + offset);
    return {first.value,
            !first.error && !second.error && first.value != 0 && first.value == second.value};
    // Plain failures retain first pointer; compressed failures return zero.
    // Compressed zero is valid. No class-address alignment/readability check here.
}
// Recovered: compact mark tags 0..2 are accepted and 3..7 rejected. Shift bounds,
// narrow-pointer overflow, read errors, and changing remote values all reject the
// result. Plain-pointer failures retain the first value; compressed failures do not.
} // namespace ocean::reconstructed::minecraft_java_object_class
