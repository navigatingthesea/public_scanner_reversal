#include "../../session/session_types.hpp"
#include <cstdint>
#include <optional>
#include <unordered_set>
#include <vector>
namespace ocean::reconstructed::minecraft_java_class_collection {
// Recovered: build one normalized class record from a native InstanceKlass.
// The record combines class/pool strings, fields, annotations, methods,
// references, superclass address, and bounded evidence bytes.
//
// Interpretation: RUIN_CLASS_CORPUS_V2 is an evidence-record marker. It is not
// itself a detection rule or a product signature.
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
struct Header {
    ByteString raw_name;
    Address raw_pool = 0, methods = 0;
};
struct Stats {
    std::uint32_t errors = 0, unsupported = 0;
};
template <class Annotation> struct Attributes {
    ByteString generic_signature;
    std::vector<ByteString> interfaces;
    std::vector<Annotation> annotations, type_annotations;
    Stats stats;
};
template <class Annotation, class Field, class Method, class Reference> struct Class {
    ByteString name;                      // native record0
    std::vector<ByteString> pool_strings; // 16, unique nonempty, stable order
    Attributes<Annotation> attributes;    // signature40,interfaces56,ann80,type104
    std::vector<Method> methods;          // 128
    std::vector<Field> fields;            // 152
    Bytes evidence;
    bool evidence_full = false; // 176,200;source158 budget semantics
    Address klass = 0, raw_context = 0;
    std::uint8_t context_flag = 0;     // 208,216,224
    std::vector<Reference> references; // 232, pool first then method refs
    Address superclass = 0;            // 256, native pointer, not its name
    Stats stats;                       // twoDWORDs at308;zero bytes264..307
};
template <class Annotation, class Field, class Method, class Reference, class Sink>
struct Contracts {
    virtual Read<Header> header(Address reader, Address klass) = 0; // 178 inclarray-class error
    virtual std::optional<Address> vm_offset(const ByteString &, const ByteString &) = 0;
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Sink evidence_sink(Address reader) = 0;      // 158, local64MiB +reader48 sharedbudget
    virtual void append(Sink &, const ByteString &) = 0; // 158, ignores nil/empty, separator8zeros
    virtual Address snapshot_pool(Address reader, Address raw_pool) = 0; // 170,nil snapshot allowed
    virtual std::vector<ByteString> pool_utf8(Address parsed_pool) = 0;  // 171
    virtual std::vector<ByteString> pool_lines(Address parsed_pool) = 0; // 171
    virtual std::vector<Field> fields(Address reader, Address klass,
                                      Address raw_pool) = 0; // 175/172/173
    virtual Attributes<Annotation> attributes(Address reader, Address klass, Address raw_pool,
                                              Address parsed_pool,
                                              std::vector<Field> &) = 0; // 177+176+168
    virtual void
    annotation_evidence(Sink &, const ByteString &,
                        const std::vector<Annotation> &) = 0; // 168 wFn raw thenlabel:target:render
    virtual std::pair<std::vector<Method>, std::vector<Reference>>
    methods(Address reader, Address raw_pool, Address method_array, Address parsed_pool, Sink &,
            Stats &) = 0; // 160 inclnestedmetadata166
    virtual std::vector<Reference> pool_references(Address parsed_pool) = 0; // 171
    virtual Bytes evidence_bytes(const Sink &) = 0;
    virtual bool evidence_full(const Sink &) = 0;
};
ByteString slash_to_dot(ByteString value) {
    for (auto &c : value)
        if (c == '/')
            c = '.';
    return value;
}
template <class Annotation, class Field, class Method, class Reference, class Sink>
Read<Class<Annotation, Field, Method, Reference>>
collect(Contracts<Annotation, Field, Method, Reference, Sink> &rt, Address reader, Address klass,
        Address context,
        std::uint8_t context_flag) { // yyk6Mm@1a9b340,320byte output pluserrorinterface
    using Output = Class<Annotation, Field, Method, Reference>;
    const auto header = rt.header(reader, klass);
    if (header.error.present)
        return {{}, header.error};
    Address superclass = 0;
    if (const auto offset = rt.vm_offset("Klass", "_super"))
        superclass = rt.read_pointer(klass + *offset)
                         .value; // original discards error, retains returned value
    auto sink = rt.evidence_sink(reader);
    rt.append(sink, "RUIN_CLASS_CORPUS_V2");
    rt.append(sink, header.value.raw_name);
    const auto name = slash_to_dot(header.value.raw_name);
    rt.append(sink, name);
    const auto pool = rt.snapshot_pool(reader, header.value.raw_pool);
    std::vector<ByteString> unique_strings;
    std::unordered_set<ByteString> seen;
    for (const auto &value : rt.pool_utf8(pool))
        if (!value.empty() && seen.insert(value).second)
            unique_strings.push_back(value);
    for (const auto &value : unique_strings)
        rt.append(sink, value);
    for (const auto &value : rt.pool_lines(pool))
        rt.append(sink, value); // duplicates retained
    auto fields = rt.fields(reader, klass, header.value.raw_pool);
    auto attributes = rt.attributes(reader, klass, header.value.raw_pool, pool, fields);
    for (const auto &value : attributes.interfaces)
        rt.append(sink, value); // empty ignored only bysink
    rt.append(sink, attributes.generic_signature);
    rt.annotation_evidence(sink, "CLASS_ANNOTATION", attributes.annotations);
    rt.annotation_evidence(sink, "CLASS_TYPE_ANNOTATION", attributes.type_annotations);
    for (const auto &field : fields) {
        rt.append(sink, field.name);
        rt.append(sink, field.descriptor);
        rt.append(sink, field.generic_signature);
        rt.annotation_evidence(sink, "FIELD_ANNOTATION:" + field.name, field.annotations);
        rt.annotation_evidence(sink, "FIELD_TYPE_ANNOTATION:" + field.name, field.type_annotations);
    }
    auto stats = attributes.stats;
    auto methods =
        rt.methods(reader, header.value.raw_pool, header.value.methods, pool, sink, stats);
    auto references = rt.pool_references(pool);
    references.insert(references.end(), methods.second.begin(),
                      methods.second.end()); // no dedup/sort
    Output out;
    out.name = name;
    out.pool_strings = std::move(unique_strings);
    out.attributes = std::move(attributes);
    out.methods = std::move(methods.first);
    out.fields = std::move(fields);
    out.evidence = rt.evidence_bytes(sink);
    out.evidence_full = rt.evidence_full(sink);
    out.klass = klass;
    out.raw_context = context;
    out.context_flag = context_flag;
    out.references = std::move(references);
    out.superclass = superclass;
    out.stats = stats;
    return {std::move(out), {}};
}
// Recovered: whole-builder paths establish evidence ordering, case-sensitive
// stable pool-string deduplication, pool-then-method reference concatenation,
// early array-class rejection, ignored superclass-read errors, context passthrough,
// and shared evidence-budget behavior. No digest is calculated in this stage.
// Interpretation: the "aero/client/Aero" test value was synthetic fixture data,
// not a recovered signature. Static values and downstream rule integration are
// wired by java_complete_evidence_pipeline.cpp.
// Unresolved: codec and operating-system primitives remain provider boundaries.
} // namespace ocean::reconstructed::minecraft_java_class_collection
