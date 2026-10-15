#include "../../session/session_types.hpp"
#include <optional>
#include <vector>

namespace ocean::reconstructed::minecraft_java_class_attributes {
using Address = std::uint64_t;

struct Error {
    bool present;
};
template<class Value>
struct Read {
    Value value;
    Error error;
};
struct Text {
    ByteString value;
    bool valid;
};
struct Stats {
    std::uint32_t errors = 0;
    std::uint32_t unsupported = 0;
};
struct PointerArray {
    std::vector<Address> values;
    bool valid;
};

template<class AnnotationRecord>
struct Metadata {
    ByteString generic_signature;
    std::vector<ByteString> interfaces;
    std::vector<AnnotationRecord> ordinary_annotations;
    std::vector<AnnotationRecord> type_annotations;
    Stats stats;
};

template<class AnnotationRecord, class FieldRecord>
struct Contracts {
    virtual std::optional<Address> vm_offset(
        const ByteString& type,
        const ByteString& field) = 0;
    virtual std::optional<Address> klass_name_offset() = 0;
    virtual Read<std::uint16_t> read16(Address) = 0;
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Text parsed_pool_utf8(Address parsed_pool, std::uint16_t) = 0;
    virtual Read<ByteString> symbol(Address reader, Address symbol) = 0;
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
    virtual void assign_field_annotations(
        Address reader,
        Address annotations_object,
        Address parsed_pool,
        std::vector<FieldRecord>& fields,
        const ByteString& vm_member,
        const ByteString& label,
        Stats&) = 0;
};

ByteString slash_to_dot(ByteString value) {
    for (auto& byte : value)
        if (byte == '/') byte = '.';
    return value;
}

template<class AnnotationRecord, class FieldRecord>
Metadata<AnnotationRecord> collect(
    Contracts<AnnotationRecord, FieldRecord>& runtime,
    Address reader,
    Address klass,
    Address raw_pool,
    Address parsed_pool,
    std::vector<FieldRecord>& fields) { // aYxPfxSN5p_@1a33ee0
    Metadata<AnnotationRecord> result;

    if (const auto signature_offset =
            runtime.vm_offset("ConstantPool", "_generic_signature_index")) {
        const auto index = runtime.read16(raw_pool + *signature_offset);
        if (!index.error.present && index.value != 0) {
            const auto signature = runtime.parsed_pool_utf8(parsed_pool, index.value);
            if (signature.valid)
                result.generic_signature = signature.value;
            else
                ++result.stats.errors;
        }
        // Missing layout, read failure, and a zero index are silent.
    }

    if (const auto interfaces_offset =
            runtime.vm_offset("InstanceKlass", "_local_interfaces")) {
        const auto array = runtime.read_pointer(klass + *interfaces_offset);
        if (!array.error.present && array.value != 0) {
            const auto interfaces = runtime.pointer_array(reader, array.value, 65536);
            if (!interfaces.valid) {
                ++result.stats.errors;
            } else {
                for (const auto interface_klass : interfaces.values) {
                    const auto name_offset = runtime.klass_name_offset();
                    if (interface_klass == 0 || !name_offset) {
                        ++result.stats.errors;
                        continue;
                    }

                    const auto name_pointer =
                        runtime.read_pointer(interface_klass + *name_offset);
                    const auto name = runtime.symbol(reader, name_pointer.value);
                    if (name_pointer.error.present || name.error.present) {
                        ++result.stats.errors;
                        continue;
                    }
                    result.interfaces.push_back(slash_to_dot(name.value));
                }
            }
        }
        // A nil interface array or failed pointer read is silent.
    }

    const auto annotations_offset =
        runtime.vm_offset("InstanceKlass", "_annotations");
    if (!annotations_offset) return result;

    const auto annotations_object =
        runtime.read_pointer(klass + *annotations_offset);
    if (annotations_object.error.present || annotations_object.value == 0)
        return result;

    const auto read_class_list = [&](const ByteString& member,
                                     const ByteString& label) {
        const auto member_offset = runtime.vm_offset("Annotations", member);
        if (!member_offset) return std::vector<AnnotationRecord>{};

        const auto blob =
            runtime.read_pointer(annotations_object.value + *member_offset);
        if (blob.error.present || blob.value == 0)
            return std::vector<AnnotationRecord>{};
        return runtime.annotation_list(
            reader, blob.value, parsed_pool, label, result.stats);
    };

    result.ordinary_annotations =
        read_class_list("_class_annotations", "annotations");
    result.type_annotations =
        read_class_list("_class_type_annotations", "type");
    runtime.assign_field_annotations(
        reader, annotations_object.value, parsed_pool, fields,
        "_fields_annotations", "annotations", result.stats);
    runtime.assign_field_annotations(
        reader, annotations_object.value, parsed_pool, fields,
        "_fields_type_annotations", "type", result.stats);
    return result;
}

// Recovered: this collector extracts the class generic signature, local
// interface names, class annotations, class type annotations, and field
// annotations from HotSpot metadata. Interface names convert `/` to `.`, while
// preserving empty values, duplicates, and order. The symbol lookup is attempted
// even when reading the symbol pointer failed, matching the original call order.
//
// Annotation parse errors and unsupported formats share `Stats` across class and
// field routes. Twenty original paths were checked. Exact annotation grammar and
// field-ordinal assignment are defined in their respective files. This readable
// reconstruction was never compiled or executed.
}
