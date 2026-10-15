#include "../../session/session_types.hpp"
#include <optional>
namespace ocean::reconstructed::minecraft_java_class_mirror {
// Recovered: read Klass::_java_mirror twice, optionally dereference OopHandle,
// decode ZGC-colored pointers, and require a readable final object address.
// The double reads are stability checks against a changing remote JVM.
using Address = std::uint64_t;
struct Read {
    Address value = 0;
    bool error = false;
};
struct Mirror {
    Address address = 0;
    bool valid = false;
};
struct Context {
    Address reader = 0;
    bool use_zgc = false, zgc_known = false;
};
struct Contracts {
    virtual std::optional<Address> klass_field_offset(Address reader, const ByteString &) = 0;
    virtual ByteString klass_field_type_or_empty(Address reader, const ByteString &) = 0;
    virtual ByteString trim_space(const ByteString &) = 0; // original strings.TrimSpace
    virtual Read read_pointer(Address reader, Address) = 0;
    virtual Mirror decode_zgc(Address reader, Address) = 0; // java_zgc_pointer_decode.cpp
    virtual bool span_readable(Address reader, Address, std::int64_t count) = 0;
};
Mirror collect(Contracts &rt, const Context &ctx, Address klass) { // hw8_bjIh@1a87d80
    const auto offset = rt.klass_field_offset(ctx.reader, "_java_mirror");
    if (!offset)
        return {};
    const auto type = rt.trim_space(rt.klass_field_type_or_empty(ctx.reader, "_java_mirror"));
    if (type != "oop" && type != "OopHandle")
        return {};
    const Address slot = klass + *offset;
    auto first = rt.read_pointer(ctx.reader, slot);
    auto second = rt.read_pointer(ctx.reader, slot); // both reads even first error
    if (first.error || second.error || first.value == 0 || first.value != second.value)
        return {};
    Address raw = first.value;
    if (type == "OopHandle") {
        first = rt.read_pointer(ctx.reader, raw);
        second = rt.read_pointer(ctx.reader, raw);
        if (first.error || second.error || first.value == 0 || first.value != second.value)
            return {};
        raw = first.value;
    }
    if (!ctx.zgc_known)
        return {};
    Address object = raw;
    if (ctx.use_zgc) {
        const auto decoded = rt.decode_zgc(ctx.reader, raw);
        if (!decoded.valid)
            return {}; // discard partial decoded data
        object = decoded.address;
    }
    return {object, rt.span_readable(ctx.reader, object, 1)};
    // Unreadable final object is retained with valid=false. No compressed-oop
    // mode is used for Klass::_java_mirror; only oop or one OopHandle indirection.
}
// Recovered: accepted types are exactly trimmed "oop" and "OopHandle". Both read
// pairs must be stable and nonzero. Unknown ZGC state rejects the mirror. A final
// unreadable object retains its address with valid=false for faithful data flow.
} // namespace ocean::reconstructed::minecraft_java_class_mirror
