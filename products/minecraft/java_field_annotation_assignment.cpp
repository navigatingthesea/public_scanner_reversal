#include "../../session/session_types.hpp"
#include <optional>
#include <vector>

namespace ocean::reconstructed::minecraft_java_field_annotations {
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;

struct Error {
    bool present;
};
template<class Value>
struct Read {
    Value value;
    Error error;
};
struct PointerArray {
    std::vector<Address> values;
    bool valid = false;
};
struct Stats {
    std::uint32_t errors = 0;
    std::uint32_t unsupported = 0;
};
struct Layout {
    // Reader-11 pointer-array body; distinct from reader-12 byte-array body.
    std::optional<Address> pointer_array_body;
};

struct Memory {
    virtual Read<std::uint32_t> count(Address reader, Address array) = 0;
    virtual Read<Bytes> exact_read(Address, std::uint64_t) = 0;
    virtual void original_bounds_panic() = 0;
};

PointerArray snapshot(
    Memory& runtime,
    const Layout& layout,
    Address reader,
    Address array,
    std::uint32_t maximum) { // aB3SSkE@1a331c0
    if (array == 0 || !layout.pointer_array_body) return {};

    const auto initial_count = runtime.count(reader, array);
    if (initial_count.error.present || initial_count.value > maximum) return {};

    const auto byte_count = std::uint64_t{initial_count.value} * 8;
    const auto first = runtime.exact_read(
        array + *layout.pointer_array_body, byte_count);
    if (first.error.present) return {};

    const auto second = runtime.exact_read(
        array + *layout.pointer_array_body, byte_count);
    const auto final_count = runtime.count(reader, array);
    if (second.error.present || final_count.error.present ||
        final_count.value != initial_count.value || first.value != second.value)
        return {};

    std::vector<Address> values;
    values.reserve(initial_count.value);
    for (std::uint32_t index = 0; index < initial_count.value; ++index) {
        const auto offset = std::size_t{index} * 8;
        if (offset > first.value.size() || first.value.size() - offset < 8) {
            runtime.original_bounds_panic();
            return {};
        }

        Address pointer = 0;
        for (unsigned byte = 0; byte < 8; ++byte)
            pointer |= Address{first.value[offset + byte]} << (byte * 8);
        values.push_back(pointer);
    }
    return {values, true};
}

template<class AnnotationRecord>
struct FieldView {
    std::uint32_t ordinal_116;
    std::vector<AnnotationRecord> ordinary_48;
    std::vector<AnnotationRecord> type_72;
};

template<class AnnotationRecord>
struct Contracts {
    virtual std::optional<Address> vm_offset(
        const ByteString& type,
        const ByteString& field) = 0;
    virtual Read<Address> read_pointer(Address) = 0;
    virtual PointerArray pointer_array(
        Address reader,
        Address array,
        std::uint32_t maximum) = 0;
    virtual std::vector<AnnotationRecord> annotation_list(
        Address reader,
        Address blob,
        Address parsed_pool,
        const ByteString& label,
        Stats&) = 0;
};

template<class AnnotationRecord>
void assign(
    Contracts<AnnotationRecord>& runtime,
    Address reader,
    Address annotations_object,
    Address parsed_pool,
    std::vector<FieldView<AnnotationRecord>>& fields,
    const ByteString& vm_member,
    const ByteString& label,
    Stats& stats) { // vrB4TXPbZB@1a36ba0
    const auto member_offset = runtime.vm_offset("Annotations", vm_member);
    if (!member_offset) return;

    const auto array_pointer =
        runtime.read_pointer(annotations_object + *member_offset);
    if (array_pointer.error.present || array_pointer.value == 0) return;

    const auto pointers = runtime.pointer_array(reader, array_pointer.value, 65536);
    if (!pointers.valid) {
        ++stats.errors;
        return;
    }

    for (auto& field : fields) {
        if (field.ordinal_116 >= pointers.values.size()) continue;
        const auto blob = pointers.values[field.ordinal_116];
        if (blob == 0) continue;

        auto annotations =
            runtime.annotation_list(reader, blob, parsed_pool, label, stats);
        if (label == "type")
            field.type_72 = annotations;
        else
            field.ordinary_48 = annotations;
    }
}

// Recovered: the pointer-array snapshot is accepted only when the count is in
// range and two body reads plus a final count agree. Nil elements, duplicates,
// and an empty array are valid. Assignment uses each field's ordinal at +116.
// A parsed result replaces the selected list even when empty; skipped ordinals
// and nil blobs leave the previous list intact. Any label other than exact
// `type` selects ordinary annotations. Pointer-layout/read absence is silent;
// an unstable pointer array increments the shared error counter once.
//
// The usual VM members are `_fields_annotations` and
// `_fields_type_annotations`. Twelve snapshot and twelve assignment routes were
// checked. This readable reconstruction was never compiled or executed.
}
