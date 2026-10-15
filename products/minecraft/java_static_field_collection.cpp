#include "../../session/session_types.hpp"
#include <limits>
#include <optional>
#include <unordered_set>
#include <utility>
#include <vector>
namespace ocean::reconstructed::minecraft_java_static_field_collection {
// Recovered: enrich non-bootstrap class records with supported static primitive,
// String, and byte[] values read through java.lang.Class mirrors. Successful
// String values are also added to the class's searchable string corpus.
using Address = std::uint64_t;
template <class T> struct Valid {
    T value;
    bool valid = false;
};
bool supported_descriptor(const ByteString &descriptor) { // i2IEIFKLsFa@1a8d400
    if (descriptor.size() == 1)
        switch (descriptor[0]) {
        case 'B':
        case 'C':
        case 'D':
        case 'F':
        case 'I':
        case 'J':
        case 'S':
        case 'Z':
            return true;
        }
    return descriptor == "Ljava/lang/String;" || descriptor == "[B";
}
template <class Class, class Value, class RuntimeContext, class Environment, class Sink>
struct Contracts {
    using Field = typename decltype(std::declval<Class &>().fields)::value_type;
    virtual RuntimeContext native_context(Address reader,
                                          std::vector<Class> &classes) = 0; // 192,giKoajRC@1a862c0
    virtual Environment
    environment_from_classes(std::vector<Class> &) = 0; // 190,o4jgsQdUKbq@1a8e9c0
    virtual Sink evidence_sink(Address reader,
                               Class &) = 0; // restoreclass176bytes/full200+sharedreader48
    virtual Valid<Address> class_mirror(RuntimeContext &, Address klass) = 0; // hw8_bjIh@1a87d80
    virtual bool mirror_class_validation_available(RuntimeContext &) = 0;     // eGZePk@1a89020
    virtual Valid<ByteString> object_class_name(RuntimeContext &,
                                                Address object) = 0; // jWpLOk@1a8ae80
    virtual Value read_value(Address reader, RuntimeContext &, Address field_address,
                             const ByteString &descriptor,
                             const Environment &) = 0; // 186,lpzyXHHV@1a8f560
    virtual Value unknown_value() = 0;                 // originalstate"unknown",otherfieldszero
    virtual void field_evidence(Sink &, const ByteString &class_name,
                                const Field &field) = 0; // 191,ewpWZVV@1a8e140
    virtual void store_evidence(Sink &, Class &) = 0;
};
template <class Class, class Value, class RuntimeContext, class Environment, class Sink>
void collect(Contracts<Class, Value, RuntimeContext, Environment, Sink> &rt, Address reader,
             std::vector<Class> &classes) { // iUxOF1vL@1a8d620
    auto context = rt.native_context(reader, classes);
    const auto environment = rt.environment_from_classes(classes); // bothcalled beforeclassloop
    for (auto &klass : classes) {
        if (klass.context_flag != 0)
            continue; // bootstrapflag from182; mode2alwayszero
        auto sink = rt.evidence_sink(reader, klass);
        std::unordered_set<ByteString> seen(klass.pool_strings.begin(), klass.pool_strings.end());
        bool mirror_attempted = false, mirror_valid = false;
        Address mirror = 0;
        for (auto &field : klass.fields) {
            // Recovered: the encoded-field parser supplies offset/valid/access
            // metadata. The legacy parser leaves all three zero, so its rows do
            // not enter this pass.
            if (!(field.access & 8) || !field.offset_valid ||
                !supported_descriptor(field.descriptor))
                continue;
            if (!mirror_attempted) {
                const auto found = rt.class_mirror(context, klass.klass);
                mirror = found.value;
                mirror_valid = found.valid;
                if (mirror_valid && rt.mirror_class_validation_available(context)) {
                    const auto name = rt.object_class_name(context, mirror);
                    mirror_valid = name.valid && name.value == "java.lang.Class";
                }
                mirror_attempted = true; // evenmissing/invalid;no retryforlaterfields
            }
            auto value = rt.unknown_value();
            if (mirror_valid &&
                Address{field.offset} <= std::numeric_limits<Address>::max() - mirror)
                value = rt.read_value(reader, context, mirror + field.offset, field.descriptor,
                                      environment);
            field.value = value; // Selected rows always receive a value, including "unknown".
            if (field.descriptor == "Ljava/lang/String;" &&
                (value.state == "value" || value.state == "truncated") && !value.text.empty() &&
                seen.insert(value.text).second)
                klass.pool_strings.push_back(value.text);
            rt.field_evidence(sink, klass.name, field); // Evidence includes unknown values.
        }
        rt.store_evidence(sink, klass);
    }
}
// Recovered: supported descriptors are all eight JVM primitives, String, and
// byte[]. Bootstrap classes, non-static fields, invalid offsets, and all other
// descriptors are skipped. Mirror lookup is lazy and attempted at most once per
// class. Address overflow leaves the selected field in the "unknown" state.
// Interpretation: a historical fixture named "mirror-invalid" actually disabled
// validation; it did not demonstrate that an invalid mirror passed validation.
} // namespace ocean::reconstructed::minecraft_java_static_field_collection
