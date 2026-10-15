#include "../../session/session_types.hpp"
#include <optional>
#include <vector>

namespace ocean::reconstructed::minecraft_java_const_method_metadata {
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;

template<class Value>
struct Read {
    Value value;
    bool error;
};
struct Stats {
    std::uint32_t errors = 0;
    std::uint32_t unsupported = 0;
};
struct Annotation88 {
    ByteString type_at40;
    Bytes data_at56;
    Bytes other_fields;
};
struct Metadata {
    ByteString signature;
    std::vector<Annotation88> annotations;
    std::vector<Annotation88> parameters;
    std::vector<Annotation88> type_annotations;
    ByteString default_value;
};
struct Blob {
    Bytes bytes;
    bool readable;
    bool unsupported;
};
struct Element {
    ByteString text;
    bool valid;
    std::uint64_t consumed;
};
struct Utf8 {
    ByteString text;
    bool valid;
};

struct Contracts {
    virtual std::optional<Address> original_vmstruct_offset(
        const ByteString& type,
        const ByteString& field) = 0;
    virtual std::optional<std::uint32_t> original_vm_constant(const ByteString&) = 0;
    virtual Read<std::uint32_t> original_read32(Address) = 0;
    virtual Read<std::uint16_t> original_read16(Address) = 0;
    virtual Read<Address> original_read_pointer(Address) = 0;
    virtual bool original_range_readable(Address, std::uint64_t) = 0;
    virtual std::vector<Annotation88> original_annotation_array(
        Address,
        Address parsed_pool,
        const ByteString& label,
        Stats&) = 0;
    virtual Blob original_annotation_blob(Address) = 0;
    virtual Element original_annotation_element(
        const Bytes&,
        Address parsed_pool,
        std::uint64_t depth) = 0;
    virtual Utf8 reviewed_parsed_pool_utf8(
        Address parsed_pool,
        std::uint16_t) = 0;
};

Metadata collect(
    Contracts& runtime,
    Address const_method,
    Address parsed_pool,
    Stats& stats) { // xUF@1a36f80
    Metadata result;

    auto flags_offset =
        runtime.original_vmstruct_offset("ConstMethod", "_flags._flags");
    if (!flags_offset)
        flags_offset = runtime.original_vmstruct_offset("ConstMethod", "_flags");
    const auto size_offset =
        runtime.original_vmstruct_offset("ConstMethod", "_constMethod_size");
    if (!flags_offset || !size_offset) return result;

    const auto has_signature =
        runtime.original_vm_constant("has_generic_signature");
    const auto has_annotations =
        runtime.original_vm_constant("has_method_annotations");
    const auto has_parameters =
        runtime.original_vm_constant("has_parameter_annotations");
    const auto has_type_annotations =
        runtime.original_vm_constant("has_type_annotations");
    const auto has_default =
        runtime.original_vm_constant("has_default_annotations");
    if (!has_signature || !has_annotations || !has_parameters ||
        !has_type_annotations || !has_default)
        return result;

    // Recovered stability check: perform all four reads and require the flags
    // and size to remain identical across both samples.
    const auto flags_first = runtime.original_read32(const_method + *flags_offset);
    const auto size_first = runtime.original_read32(const_method + *size_offset);
    const auto flags_second = runtime.original_read32(const_method + *flags_offset);
    const auto size_second = runtime.original_read32(const_method + *size_offset);
    if (flags_first.error || size_first.error || flags_second.error ||
        size_second.error || flags_first.value != flags_second.value ||
        size_first.value != size_second.value || size_first.value == 0 ||
        size_first.value > 1000000) {
        ++stats.errors;
        return result;
    }

    const auto total_bytes = std::uint64_t{size_first.value} * 8;
    const auto end = const_method + total_bytes;
    if (end < const_method || !runtime.original_range_readable(end - 1, 1)) {
        ++stats.errors;
        return result;
    }

    const auto flags = flags_first.value;
    std::uint64_t trailing_bytes_required = 0;
    for (const auto mask : {
             *has_annotations, *has_parameters, *has_type_annotations, *has_default})
        if ((flags & mask) != 0) trailing_bytes_required += 8;
    if ((flags & *has_signature) != 0) trailing_bytes_required += 2;
    if (total_bytes < trailing_bytes_required) {
        ++stats.errors;
        return result;
    }

    auto cursor = end;
    const auto read_annotation_array = [&](std::uint32_t mask,
                                           const ByteString& label,
                                           std::vector<Annotation88>& destination) {
        if ((flags & mask) == 0) return;
        cursor -= 8;
        const auto pointer = runtime.original_read_pointer(cursor);
        if (pointer.error || pointer.value == 0) {
            ++stats.errors;
            return;
        }
        destination = runtime.original_annotation_array(
            pointer.value, parsed_pool, label, stats);
    };

    // Recovered storage order from the end of ConstMethod.
    read_annotation_array(*has_annotations, "annotations", result.annotations);
    read_annotation_array(*has_parameters, "parameters", result.parameters);
    read_annotation_array(*has_type_annotations, "type", result.type_annotations);

    if ((flags & *has_default) != 0) {
        cursor -= 8;
        const auto pointer = runtime.original_read_pointer(cursor);
        const auto blob = runtime.original_annotation_blob(pointer.value);
        if (blob.unsupported) {
            ++stats.unsupported;
        } else if (!pointer.error && pointer.value != 0 && blob.readable) {
            const auto element = runtime.original_annotation_element(
                blob.bytes, parsed_pool, 0);
            if (element.valid && element.consumed == blob.bytes.size())
                result.default_value = element.text;
            else
                ++stats.errors;
        } else {
            ++stats.errors;
        }
    }

    if ((flags & *has_signature) != 0) {
        if (cursor < const_method + 2) {
            ++stats.errors;
        } else {
            const auto index = runtime.original_read16(cursor - 2);
            if (!index.error) {
                const auto signature =
                    runtime.reviewed_parsed_pool_utf8(parsed_pool, index.value);
                if (signature.valid)
                    result.signature = signature.text;
                else
                    ++stats.errors;
            }
            // Recovered quirk: a signature-index read error adds no error count.
        }
    }
    return result;
}

// Recovered: this function reads generic signature, method annotations,
// parameter annotations, type annotations, and annotation default from the
// trailing ConstMethod metadata. Feature bits come from runtime VM constants;
// no fixed bit positions are assumed. The annotation-default blob is requested
// even when its pointer read failed, preserving original call order.
//
// The parent method collector intentionally swaps the ordinary and parameter
// evidence labels; see java_raw_method_control_flow.cpp. Fourteen layout and
// attribute routes were checked. Annotation grammar is defined in
// java_annotation_grammar.cpp. This readable source was never compiled or run.
}
