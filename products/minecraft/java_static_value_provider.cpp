#include "../../session/session_types.hpp"
#include <vector>
namespace ocean::reconstructed::minecraft_java_static_value_provider {
// Recovered: dispatch a selected static field to the primitive, String, or byte[]
// decoder and reject a reference value if its raw slot changes during decoding.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Read {
    Bytes value;
    bool error = false;
};
struct Reference {
    Address object = 0, raw = 0;
    bool valid = false, is_null = false;
};
template <class Value, class RuntimeContext, class Environment> struct Contracts {
    virtual Read exact_read(Address reader, Address address, std::size_t bytes) = 0;
    virtual Value decode_primitive(const ByteString &, const Bytes &) = 0;  // 185,112bytevalue
    virtual Reference stable_reference(RuntimeContext &, Address slot) = 0; // ejkacdBuGME@1a87a40
    virtual Value read_byte_array(Address reader, RuntimeContext &,
                                  Address object) = 0; // i6RSy40HwGq@1a90aa0
    virtual Value read_string(Address reader, RuntimeContext &, Address object,
                              const Environment &) = 0; // xoBFxvoqU@1a917a0
    virtual bool reference_still_matches(RuntimeContext &, Address slot,
                                         Address original_raw) = 0; // iUuwwY0RIXSe@1a87cc0
    virtual Value unknown_value() = 0;
    virtual Value null_value() = 0; // state"null",otherszero
};
std::size_t primitive_width(const ByteString &descriptor) {
    if (descriptor.size() != 1)
        return 0;
    switch (descriptor[0]) {
    case 'B':
    case 'Z':
        return 1;
    case 'C':
    case 'S':
        return 2;
    case 'I':
    case 'F':
        return 4;
    case 'J':
    case 'D':
        return 8;
    default:
        return 0;
    }
}
template <class Value, class RuntimeContext, class Environment>
Value read(Contracts<Value, RuntimeContext, Environment> &rt, Address reader,
           RuntimeContext &context, Address address, const ByteString &descriptor,
           const Environment &environment) { // lpzyXHHV@1a8f560
    const auto width = primitive_width(descriptor);
    if (width) {
        const auto first = rt.exact_read(reader, address, width);
        const auto second = rt.exact_read(reader, address, width); // evenfirsterror
        if (first.error || second.error || first.value != second.value)
            return rt.unknown_value();
        return rt.decode_primitive(descriptor, first.value);
        // Recovered: this layer checks only equality and error state. A hypothetical
        // short-but-equal result can still reach the primitive decoder's bounds
        // panic; exact_read normally guarantees the requested size.
    }
    const auto reference = rt.stable_reference(context, address);
    if (!reference.valid)
        return rt.unknown_value();
    if (reference.is_null)
        return rt.null_value(); // BEFOREsupportedreferencetypegate
    Value value = rt.unknown_value();
    if (descriptor == "[B")
        value = rt.read_byte_array(reader, context, reference.object);
    else if (descriptor == "Ljava/lang/String;")
        value = rt.read_string(reader, context, reference.object, environment);
    else
        return value; // Unsupported objects still incur the initial stable-reference read.
    if (!rt.reference_still_matches(context, address, reference.raw))
        return rt.unknown_value();
    return value; // Child decoders own any additional object-address validation.
}
// Recovered: primitive reads are attempted twice even when the first fails;
// changed bytes become unknown; a null reference becomes the explicit null state;
// and a decoded String/byte[] is discarded if its source slot changes afterward.
// Recovered ABI evidence identifies a 112-byte value returned through caller
// storage. Byte-array and String object layouts are implemented separately.
} // namespace ocean::reconstructed::minecraft_java_static_value_provider
