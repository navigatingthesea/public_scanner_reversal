#include "../../session/session_types.hpp"
#include <algorithm>
#include <limits>
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_byte_array_value {
// Recovered: validate and copy a Java byte[] twice, reread its length, and cap
// retained data at 64 KiB while recording whether the value was truncated.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
template <class T> struct Read {
    T value;
    bool error = false;
};
template <class T> struct Valid {
    T value;
    bool valid = false;
};
struct Value {
    ByteString state = "unknown";
    Bytes bytes;
}; // state0,bytearraypayload88 of112bytevalue;otherfieldszero
template <class RuntimeContext> struct Contracts {
    virtual bool object_class_validation_available(RuntimeContext &) = 0;
    virtual Valid<ByteString> object_class_name(RuntimeContext &, Address) = 0;
    virtual std::optional<Address> vm_offset(Address reader, const ByteString &type,
                                             const ByteString &member) = 0;
    virtual ByteString vm_field_type(Address reader, const ByteString &type,
                                     const ByteString &member) = 0;
    virtual ByteString original_trim_space(const ByteString &) = 0;
    virtual Read<std::uint32_t> read32(Address reader, Address) = 0;
    virtual Read<Bytes> exact_read(Address reader, Address, std::size_t) = 0;
};
template <class RuntimeContext>
Value collect(Contracts<RuntimeContext> &rt, Address reader, RuntimeContext &context,
              Address object) { // i6RSy40HwGq@1a90aa0
    if (rt.object_class_validation_available(context)) {
        const auto name = rt.object_class_name(context, object);
        if (!name.valid || name.value != "[B")
            return {};
    }
    const auto offset = rt.vm_offset(reader, "arrayOopDesc", "_length");
    const auto type = rt.original_trim_space(rt.vm_field_type(reader, "arrayOopDesc", "_length"));
    if (!offset || type != "int" || *offset > std::numeric_limits<Address>::max() - 4)
        return {};
    const auto first_length = rt.read32(reader, object + *offset);
    const auto second_length = rt.read32(reader, object + *offset); // evenfirsterror
    if (first_length.error || second_length.error || first_length.value != second_length.value ||
        first_length.value >= 0x80000000)
        return {};
    const auto count = std::min(first_length.value, std::uint32_t{65536});
    // Recovered: unsigned address arithmetic is preserved; the original adds no
    // separate overflow check for object + offset + 4.
    const Address data = object + *offset + 4;
    const auto first = rt.exact_read(reader, data, count);
    const auto second = rt.exact_read(reader, data, count);
    const auto last_length = rt.read32(reader, object + *offset); // After both body reads.
    if (first.error || second.error || last_length.error ||
        last_length.value != first_length.value || first.value != second.value)
        return {};
    return {first_length.value > 65536 ? "truncated" : "value",
            first.value}; // Retain the first stable body buffer.
}
// Recovered: routes cover class validation, missing/wrong layout metadata,
// negative signed lengths, all length/body read failures, changing data, empty
// arrays, and 65537-byte truncation to 65536 bytes. This function records only
// retained bytes and state; it adds no full-length or hash field.
} // namespace ocean::reconstructed::minecraft_java_byte_array_value
