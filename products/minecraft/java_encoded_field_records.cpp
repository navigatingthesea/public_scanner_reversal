#include "../../session/session_types.hpp"
#include <functional>
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_encoded_fields {
// Recovered: decode HotSpot's compressed UNSIGNED5 field stream and resolve
// field names, descriptors, and optional signatures through the constant pool.
//
// Unresolved: metadata words at record offsets 104 and 112 remain opaque; no
// recovered downstream rule assigns them a stronger semantic meaning.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Error {
    bool present = false;
    ByteString message;
};
template <class T> struct Read {
    T value;
    Error error;
};
struct Number {
    std::uint32_t value = 0;
    std::int64_t next = 0;
    Error error;
};
Number unsigned_five(const Bytes &bytes, std::int64_t position) { // xqkQK4w@1a4cc20
    const auto fail = [&](const ByteString &reason) { return Number{0, position, {true, reason}}; };
    if (position < 0 || std::uint64_t(position) >= bytes.size())
        return fail("truncated UNSIGNED5");
    const auto first = bytes[position];
    if (first == 0)
        return fail("invalid UNSIGNED5");
    std::uint64_t value = std::uint8_t(first - 1);
    if (value < 191)
        return {std::uint32_t(value), position + 1, {}};
    for (unsigned k = 1; k <= 4; ++k) {
        if (std::uint64_t(position) + k >= bytes.size())
            return fail("truncated UNSIGNED5");
        const auto byte = bytes[position + k];
        if (byte == 0)
            return fail("invalid UNSIGNED5");
        value += std::uint64_t(std::uint8_t(byte - 1)) << (k * 6); // addition, not bitwise OR
        if (byte < 192 || k == 4) {
            if (value > 0xffffffff)
                return fail("UNSIGNED5 overflow");
            return {std::uint32_t(value), position + std::int64_t(k) + 1, {}};
        }
    }
    return fail(
        "UNSIGNED5 too long"); // original contains this branch; fixed k==4 termination prevents it
}
struct Field { // original120byte layout, unused value/annotation fields initially zero
    ByteString name, descriptor, generic_signature;
    std::uint32_t metadata_104 = 0, valid_108 = 1, metadata_112 = 0, ordinal_116 = 0;
};
using Utf8Lookup = std::function<Read<ByteString>(std::uint16_t)>;
std::optional<std::vector<Field>> parse(const Bytes &bytes,
                                        const Utf8Lookup &lookup) { // gX12DoB@1a4b820
    std::int64_t position = 0;
    std::vector<Field> out;
    auto count = unsigned_five(bytes, position);
    if (count.error.present)
        return {};
    position = count.next;
    auto ignored_header = unsigned_five(bytes, position);
    if (ignored_header.error.present)
        return {};
    position = ignored_header.next;
    if (count.value > 65536)
        return {}; // second header is decoded BEFORE this check
    for (std::uint32_t ordinal = 0; ordinal < count.value; ++ordinal) {
        std::uint32_t base[5];
        bool failed = false;
        for (unsigned k = 0; k < 5; ++k) {
            const auto value = unsigned_five(bytes, position);
            if (value.error.present) {
                failed = true;
                break;
            }
            position = value.next;
            base[k] = value.value;
        }
        if (failed)
            break; // retain earlier completed rows
        const auto name_index = base[0], descriptor_index = base[1], metadata_first = base[2],
                   metadata_second = base[3], flags = base[4];
        std::uint32_t signature_index = 0;
        for (const auto mask : {std::uint32_t(1), std::uint32_t(4), std::uint32_t(16)}) {
            if (flags & mask) {
                const auto extra = unsigned_five(bytes, position);
                if (extra.error.present) {
                    failed = true;
                    break;
                }
                position = extra.next;
                if (mask == 4)
                    signature_index = extra.value;
            }
        }
        // Assembly1a4baa7 restores ORIGINAL flags after each optional read. The
        // draft incorrectly makes some later flags appear to be decoded values.
        if (failed)
            break;
        if (name_index > 65535 || descriptor_index > 65535 || (flags & 2))
            continue;
        const auto name = lookup(std::uint16_t(name_index));
        const auto descriptor =
            lookup(std::uint16_t(descriptor_index)); // attempted despite name error
        if (name.error.present || descriptor.error.present)
            continue;
        ByteString signature;
        if (signature_index != 0 && signature_index < 65536)
            signature = lookup(std::uint16_t(signature_index)).value; // error deliberately ignored
        out.push_back(
            {name.value, descriptor.value, signature, metadata_first, 1, metadata_second, ordinal});
    }
    return out; // successful nonnil slice, even empty; trailing ignored; no nonempty-string
                // validation
}
struct Layout {
    std::optional<Address> field_stream, byte_array_body;
}; // reader32/12
struct Contracts {
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Read<std::uint32_t> array_count(Address reader,
                                            Address array) = 0; // wMW/source167; cap2m
    virtual Read<Bytes> exact_read(Address, std::uint64_t) = 0;
    virtual Read<ByteString> native_pool_utf8(Address reader, Address pool,
                                              std::uint16_t) = 0; // jjCB/source159
};
std::optional<std::vector<Field>> collect(Contracts &runtime, const Layout &layout, Address reader,
                                          Address klass, Address pool) { // cgUD5W@1a4b6a0
    if (!layout.field_stream || !layout.byte_array_body)
        return {};
    const auto array =
        runtime.read_pointer(klass + *layout.field_stream); // no explicit klass==0 guard
    if (array.error.present || !array.value)
        return {};
    const auto length = runtime.array_count(reader, array.value);
    if (length.error.present)
        return {};
    const auto bytes = runtime.exact_read(array.value + *layout.byte_array_body,
                                          std::min(length.value, std::uint32_t(1000000)));
    if (bytes.error.present)
        return {};
    return parse(bytes.value, [&](std::uint16_t index) {
        return runtime.native_pool_utf8(reader, pool, index);
    }); // cgUD.func1@1a4b7e0
}
// Recovered: nullopt preserves a nil Go slice, while an optional empty vector is
// a non-nil empty result that suppresses the legacy parser. Name/descriptor
// failures drop one row; signature failures retain the provider's returned text.
// Partial records stop parsing while preserving completed rows and original order.
// Unresolved: metadata fields 104 and 112 are real decoded values, but no recovered
// consumer establishes their meaning.
} // namespace ocean::reconstructed::minecraft_java_encoded_fields
