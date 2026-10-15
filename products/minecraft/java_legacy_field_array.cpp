#include "../../session/session_types.hpp"
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_legacy_fields {
// Recovered: fallback parser for the older InstanceKlass::_fields Array<u2>
// representation. It resolves only name/descriptor pairs and ordinals; those
// rows intentionally lack encoded offsets and cannot enter static-value reads.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Error {
    bool present;
};
template <class T> struct Read {
    T value;
    Error error;
};
struct Field { // original120byte output; metadata/value/annotation fields remainzero
    ByteString name, descriptor, generic_signature;
    std::uint32_t metadata_104 = 0, valid_108 = 0, metadata_112 = 0, ordinal_116 = 0;
};
struct Contracts {
    virtual std::optional<Address> vm_offset(const ByteString &type, const ByteString &field) = 0;
    virtual std::optional<std::uint64_t> vm_constant(const ByteString &name) = 0;
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Read<std::uint16_t> read16(Address) = 0;
    virtual Read<Bytes> exact_read(Address, std::uint64_t) = 0;
    virtual Read<ByteString> native_pool_utf8(Address reader, Address pool,
                                              std::uint16_t) = 0; // 159
};
std::optional<std::vector<Field>> collect(Contracts &runtime, Address reader, Address klass,
                                          Address pool) { // gXa3S0Atu@1a4bea0
    const auto fields_offset = runtime.vm_offset("InstanceKlass", "_fields");
    const auto count_offset = runtime.vm_offset("InstanceKlass", "_java_fields_count");
    auto body_offset = runtime.vm_offset("Array<u2>", "_data[0]");
    if (!body_offset)
        body_offset = runtime.vm_offset("Array<u2>", "_data");
    const auto configured_slots = runtime.vm_constant("FieldInfo::field_slots");
    const auto slots = configured_slots.value_or(6); // missing constant uses6, presentzero rejected
    if (!fields_offset || !count_offset || !body_offset || slots < 3 || slots > 64)
        return {};
    const auto fields = runtime.read_pointer(klass + *fields_offset);
    if (fields.error.present || !fields.value)
        return {};
    const auto count = runtime.read16(klass + *count_offset);
    if (count.error.present)
        return {};
    const auto bytes =
        runtime.exact_read(fields.value + *body_offset, std::uint64_t(count.value) * slots * 2);
    if (bytes.error.present)
        return {};
    std::vector<std::uint16_t> words;
    for (std::size_t k = 0; k + 1 < bytes.value.size(); k += 2)
        words.push_back(std::uint16_t(bytes.value[k]) | (std::uint16_t(bytes.value[k + 1]) << 8));
    std::vector<Field> out;
    for (std::uint32_t ordinal = 0; ordinal < count.value; ++ordinal) {
        const auto start = std::uint64_t(ordinal) * slots;
        if (start + 2 >= words.size())
            break;
        const auto name = runtime.native_pool_utf8(reader, pool, words[start + 1]);
        const auto descriptor = runtime.native_pool_utf8(reader, pool, words[start + 2]);
        out.push_back(
            {name.value, descriptor.value, {}, 0, 0, 0, ordinal}); // Both lookup errors ignored.
    }
    return out;
}
// Recovered: nullopt represents nil data; a successful empty vector remains
// non-nil. The first word and remaining metadata words in each stride are ignored.
// Lookup errors can leave empty/partial names or descriptors in retained rows.
// Unlike the encoded parser, these rows have no valid offset or generic signature.
// The body is read once; this stage performs no stability reread.
} // namespace ocean::reconstructed::minecraft_java_legacy_fields
