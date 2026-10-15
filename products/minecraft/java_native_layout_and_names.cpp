#include "../../session/session_types.hpp"
#include <optional>
#include <algorithm>
namespace ocean::reconstructed::minecraft_java_native_names {
// Recovered: validate object-header metadata, perform bounded native string
// reads, and resolve an object's class name from either the collected-class map
// or the Klass::_name Symbol fallback.
using Address = std::uint64_t;
template <class T> struct Read {
    T value;
    bool error = false;
};
struct Name {
    ByteString text;
    bool valid = false;
};
struct Region {
    Address base = 0, size = 0;
};
struct Context {
    Address reader = 0;
    bool compact_headers = false, compact_headers_known = false;
    bool compressed_class_pointers = false, class_encoding_known = false;
};
struct Contracts {
    virtual bool has_vm_constant(Address reader, const ByteString &) = 0;
    virtual bool has_field_offset(Address reader, const ByteString &type,
                                  const ByteString &member) = 0;
    virtual std::optional<Region> containing_region(Address process,
                                                    Address address) = 0; // cZkEv_ provider
    virtual bool span_readable(Address process, Address address, std::int64_t count) = 0;
    virtual Read<ByteString> read_bytes(Address process, Address address, std::uint64_t count) = 0;
    virtual Read<Address>
    decode_object_class(const Context &, Address object) = 0; // t9eW5d; error here means !valid
    virtual std::optional<ByteString> class_record_name(const Context &, Address klass) = 0;
    virtual std::optional<Address>
    cached_klass_name_offset(Address reader) = 0; // reader224, not reader28
    virtual Address process_for_reader(Address reader) = 0;
    virtual Read<Address> read_pointer(Address process, Address) = 0;
    virtual Read<ByteString> read_symbol(Address reader, Address) = 0;
};
bool class_layout_available(Contracts &rt, const Context &ctx) { // eGZePk@1a89020
    if (!ctx.compact_headers_known)
        return false;
    if (ctx.compact_headers) {
        if (!rt.has_vm_constant(ctx.reader, "markWord::klass_shift"))
            return false;
        if (!ctx.class_encoding_known || !ctx.compressed_class_pointers)
            return false;
        return rt.has_field_offset(ctx.reader, "oopDesc", "_mark");
    }
    if (!ctx.class_encoding_known)
        return false;
    return rt.has_field_offset(ctx.reader, "oopDesc",
                               ctx.compressed_class_pointers ? "_metadata._compressed_klass"
                                                             : "_metadata._klass");
    // Presence is checked here; constant value range is checked by the decoder.
}
bool span_within_region(Contracts &rt, Address process, Address address,
                        std::int64_t count) { // wTZoNC6@1a8cec0
    if (count < 0)
        return false;
    const auto region = rt.containing_region(process, address);
    if (!region)
        return false;
    const Address end = address + static_cast<std::uint64_t>(count);
    if (end < address)
        return false;
    return end <= region->base + region->size;
    // No separate lower-bound test here: containing_region owns that selection.
    // An empty span at the supplied region's end is accepted. The region-end
    // addition itself has no overflow check in this helper.
}
Read<ByteString> read_c_string(Contracts &rt, Address process,
                               Address address) { // wvG7BYMkaXq6@1a64700
    if (address == 0 || !rt.span_readable(process, address, 1))
        return {{}, true}; //"invalid C string pointer"
    auto bytes = rt.read_bytes(process, address, 512);
    if (bytes.error)
        return {{}, true}; // original native-read error propagated
    const auto nul = bytes.value.find(char(0));
    if (nul != ByteString::npos)
        bytes.value.resize(nul);
    return bytes; // short/empty reads and 512 bytes without a NUL are accepted; raw bytes preserved
}
Name object_class_name(Contracts &rt, const Context &ctx, Address object) { // jWpLOk@1a8ae80
    const auto klass = rt.decode_object_class(ctx, object);
    if (klass.error)
        return {};
    const auto cached = rt.class_record_name(ctx, klass.value);
    if (cached)
        return {*cached, true}; // includes an empty cached name; no slash normalization here
    const auto name_offset = rt.cached_klass_name_offset(ctx.reader);
    if (!name_offset)
        return {};
    const auto pointer =
        rt.read_pointer(rt.process_for_reader(ctx.reader), klass.value + *name_offset);
    auto symbol = rt.read_symbol(ctx.reader, pointer.value); // still called after pointer read
                                                             // error
    std::replace(symbol.value.begin(), symbol.value.end(), '/', '.');
    return {std::move(symbol.value), !pointer.error && !symbol.error};
    // Partial normalized text is retained with valid=false. Successful empty
    // symbols are valid; nonempty-name validation is not added by this routine.
}
// Recovered: 46 paths cover all 16 context-flag combinations, missing metadata,
// cached and fallback class names, bounded C strings, and region-span checks.
// Interpretation: containing_region owns the lower-bound test; this helper checks
// only overflow and the selected region's upper bound.
} // namespace ocean::reconstructed::minecraft_java_native_names
