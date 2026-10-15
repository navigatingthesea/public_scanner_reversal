#include "../../session/session_types.hpp"
#include <algorithm>
#include <optional>
#include <vector>

namespace ocean::reconstructed::minecraft_java_method_producer {
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;

template<class Value>
struct Read {
    Value value;
    bool error;
};
struct Annotation88 {
    ByteString type_at40;
    Bytes data_at56;
    Bytes other_fields;
};
struct ConstMetadata {
    ByteString primary_text_at32;
    ByteString secondary_text_at120;
    std::vector<Annotation88> annotations_at48;
    std::vector<Annotation88> parameter_annotations_at72;
    std::vector<Annotation88> type_annotations_at96;
};
struct Snapshot {
    Bytes bytecode;
    ByteString sha256;
    bool truncated;
};
struct Opcodes {
    Bytes values;
    bool complete;
};
struct Reference72 {
    std::uint64_t index;
    ByteString kind;
    ByteString owner;
    ByteString member;
    ByteString descriptor;
};
struct References {
    std::vector<Reference72> rows;
    std::vector<ByteString> text;
    bool valid;
};

// Logical view of the recovered 296-byte method record. Suffixes retain native
// offsets where the original field name was unavailable.
struct Method {
    ByteString name;
    ByteString descriptor;
    ConstMetadata metadata;
    bool native136 = false;
    bool abstract137 = false;
    Snapshot bytecode144;
    std::uint16_t code_size168 = 0;
    std::uint32_t invocation196 = 0;
    std::uint32_t raw_counter200 = 0;
    bool invocation_valid204 = false;
    Address native_address208 = 0;
    bool native_reads_success216 = false;
    ByteString owner224;
    ByteString backing240;
    bool stable256 = false;
    bool query257 = false;
    bool private_exec258 = false;
    bool missing259 = false;
    Opcodes opcode264{{}, false};
};

struct Layout {
    std::optional<Address> array_body;
    std::optional<Address> method_const;
    std::optional<Address> name_index;
    std::optional<Address> descriptor_index;
    std::optional<Address> access_flags;
    std::optional<Address> code_size;
    std::optional<Address> code_body;
    std::optional<Address> method_counters;
    std::optional<Address> counter_field;
    std::optional<Address> counter_body;
    std::optional<Address> native_slot;
    bool fallback_counter_shift_one = false;
};
struct Result {
    std::vector<Method> methods;
    std::vector<Reference72> references;
};

struct Contracts {
    virtual Read<std::uint32_t> reviewed_method_array_count(Address) = 0; // wMW@1a48ce0
    virtual Read<Address> original_read_pointer(Address) = 0;
    virtual Read<std::uint16_t> original_read16(Address) = 0;
    virtual Read<std::uint32_t> original_read32(Address) = 0;
    virtual Read<Bytes> original_exact_read_bytes(Address, std::uint64_t) = 0;
    virtual Read<ByteString> reviewed_pool_utf8(Address, std::uint16_t) = 0;
    virtual ConstMetadata original_const_method_metadata(
        Address,
        Address parsed_pool,
        std::uint64_t auxiliary) = 0;
    virtual void reviewed_append_evidence(const Bytes&) = 0;
    virtual void original_annotation_evidence(
        const ByteString& label,
        const std::vector<Annotation88>&) = 0;
    virtual Snapshot reviewed_bytecode_snapshot(const Bytes&) = 0;
    virtual Opcodes reviewed_instruction_walk(const Bytes&) = 0;
    virtual References original_resolve_bytecode_references(
        const Bytes&,
        Address parsed_pool) = 0;
    virtual ByteString original_quote_to_ascii(const ByteString&) = 0; // cW@1a4e120
    virtual std::optional<std::uint32_t> original_vm_constant(const ByteString&) = 0;
    virtual std::pair<ByteString, ByteString> reviewed_native_module_owner(Address) = 0;
    virtual void reviewed_native_address_classifier(Method&, Address original_slot) = 0;
};

Bytes as_bytes(const ByteString& text) {
    return {text.begin(), text.end()};
}

Result collect(
    Contracts& runtime,
    const Layout& layout,
    Address pool,
    Address method_array,
    Address parsed_pool,
    std::uint64_t auxiliary) { // ndFCF9@1a490c0..1a4b480
    Result result;
    if (pool == 0 || method_array == 0 || !layout.array_body ||
        !layout.method_const || !layout.name_index || !layout.descriptor_index)
        return result;

    const auto count = runtime.reviewed_method_array_count(method_array);
    if (count.error) return result;

    const auto bounded_count = std::min(count.value, std::uint32_t{65536});
    result.methods.reserve(bounded_count);
    for (std::uint32_t index = 0; index < bounded_count; ++index) {
        const auto method_pointer = runtime.original_read_pointer(
            method_array + *layout.array_body + std::uint64_t{index} * 8);
        if (method_pointer.error || method_pointer.value == 0) continue;

        const auto const_method = runtime.original_read_pointer(
            method_pointer.value + *layout.method_const);
        if (const_method.error || const_method.value == 0) continue;

        const auto name_index = runtime.original_read16(
            const_method.value + *layout.name_index);
        if (name_index.error) continue;
        const auto descriptor_index = runtime.original_read16(
            const_method.value + *layout.descriptor_index);
        if (descriptor_index.error) continue;

        const auto name = runtime.reviewed_pool_utf8(pool, name_index.value);
        const auto descriptor = runtime.reviewed_pool_utf8(
            pool, descriptor_index.value); // Attempted even if name failed.
        if (name.error || descriptor.error) continue;

        Method method{};
        method.name = name.value;
        method.descriptor = descriptor.value;
        runtime.reviewed_append_evidence(as_bytes(method.name));
        runtime.reviewed_append_evidence(as_bytes(method.descriptor));

        method.metadata = runtime.original_const_method_metadata(
            const_method.value, parsed_pool, auxiliary);
        runtime.reviewed_append_evidence(
            as_bytes(method.metadata.primary_text_at32));
        runtime.reviewed_append_evidence(
            as_bytes(method.metadata.secondary_text_at120));

        // Recovered quirk: the caller swaps ordinary/parameter labels relative
        // to the metadata producer's fields.
        runtime.original_annotation_evidence(
            "METHOD_ANNOTATION:" + method.name,
            method.metadata.parameter_annotations_at72);
        runtime.original_annotation_evidence(
            "METHOD_PARAMETER_ANNOTATION:" + method.name,
            method.metadata.annotations_at48);
        runtime.original_annotation_evidence(
            "METHOD_TYPE_ANNOTATION:" + method.name,
            method.metadata.type_annotations_at96);

        if (layout.access_flags) {
            const auto flags = runtime.original_read32(
                method_pointer.value + *layout.access_flags);
            if (!flags.error) {
                method.native136 = (flags.value & 0x100) != 0;
                method.abstract137 = (flags.value & 0x400) != 0;
            }
        }

        if (layout.code_size && layout.code_body) {
            const auto length = runtime.original_read16(
                const_method.value + *layout.code_size);
            if (!length.error) {
                method.code_size168 = length.value;
                const auto first = runtime.original_exact_read_bytes(
                    const_method.value + *layout.code_body, length.value);
                if (!first.error) {
                    const auto second = runtime.original_exact_read_bytes(
                        const_method.value + *layout.code_body, length.value);
                    if (second.error || second.value != first.value) {
                        // Recovered: unstable bytecode emits a partial method and
                        // skips this method's counter and native-slot branches.
                        result.methods.push_back(method);
                        continue;
                    }

                    runtime.reviewed_append_evidence(first.value);
                    method.bytecode144 = runtime.reviewed_bytecode_snapshot(first.value);
                    method.opcode264 = runtime.reviewed_instruction_walk(first.value);

                    const auto references =
                        runtime.original_resolve_bytecode_references(first.value, parsed_pool);
                    if (references.valid) {
                        result.references.insert(
                            result.references.end(),
                            references.rows.begin(),
                            references.rows.end());
                        for (auto text : references.text) {
                            if (text.size() >= 3 && text.compare(0, 3, "BC:") == 0)
                                text.erase(0, 3);
                            runtime.reviewed_append_evidence(as_bytes(
                                "BC:" + runtime.original_quote_to_ascii(method.name) +
                                ":" + runtime.original_quote_to_ascii(method.descriptor) +
                                ":" + text));
                        }
                    }
                }
            }
        }

        if (layout.method_counters && layout.counter_field && layout.counter_body) {
            const auto counter_pointer = runtime.original_read_pointer(
                method_pointer.value + *layout.method_counters);
            if (!counter_pointer.error && counter_pointer.value != 0) {
                const auto counter = runtime.original_read32(
                    counter_pointer.value + *layout.counter_field + *layout.counter_body);
                if (!counter.error) {
                    method.raw_counter200 = counter.value;
                    const auto shift = runtime.original_vm_constant(
                        "InvocationCounter::count_shift");
                    if (shift && *shift <= 31) {
                        method.invocation196 = counter.value >> *shift;
                        method.invocation_valid204 = true;
                    } else if (layout.fallback_counter_shift_one) {
                        method.invocation196 = counter.value >> 1;
                        method.invocation_valid204 = true;
                    }
                }
            }
        }

        if (method.native136 && layout.native_slot) {
            const auto slot = method_pointer.value + *layout.native_slot;
            const auto first = runtime.original_read_pointer(slot);
            const auto second = runtime.original_read_pointer(slot + 8);
            if (!first.error && !second.error) {
                method.native_address208 = first.value;
                method.native_reads_success216 = true;
                const auto owner = runtime.reviewed_native_module_owner(first.value);
                method.owner224 = owner.first;
                method.backing240 = owner.second;
                runtime.reviewed_native_address_classifier(method, slot);
            }
        }

        result.methods.push_back(method);
    }
    return result;
}

// Recovered: this is the central per-class method collector. It emits method
// names, descriptors, ConstMethod metadata, annotation evidence, stable bytecode,
// bytecode hashes/opcodes/references, invocation counters, and native-address
// metadata. It does not issue a detection verdict. Method and reference order and
// duplicates are preserved; the method count is capped at 65,536.
//
// Optional VMStruct offsets distinguish a present offset of zero from a missing
// layout. A failed first bytecode read still permits counter/native processing;
// an unstable successful read produces a partial row and skips them. Twenty-three
// original control-flow fixtures were checked. This source was never compiled or
// executed.
}
