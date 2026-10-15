#include "java_hotspot_vmstructs.hpp"
namespace ocean::reconstructed::minecraft_hotspot_review {
// Recovered: bind named VMStruct entries into the compact reader layout used by
// downstream collectors. Missing entries remain empty bindings; construction
// itself does not reject a partially supported JVM layout.
static ReaderBinding offset(const VmLayout &v, const char *type, const char *field) {
    auto i = v.instance_offsets.find({type, field});
    return {i == v.instance_offsets.end() ? std::nullopt : std::optional<Word>(i->second)};
}
static ReaderBinding size(const VmLayout &v, const char *type) {
    auto i = v.type_sizes.find(type);
    return {i == v.type_sizes.end() ? std::nullopt : std::optional<Word>(i->second)};
}
// piP0hJP@1a413c0. Missing map entries remain empty bindings; this constructor
// does not return an error. Later readers decide whether each optional layout is usable.
NativeJavaReader build_native_java_reader(Word context, const VmLayout &v) {
    NativeJavaReader r;
    r.context = context;
    r.layout = &v;
    r.array_klass_length = offset(v, "Array<Klass*>", "_length");
    r.array_u1_data = offset(v, "Array<u1>", "_data[0]");
    if (auto i = v.constants.find("InstanceKlass::loaded"); i != v.constants.end())
        r.instance_klass_loaded = i->second;
    r.array_klass_data = offset(v, "Array<Klass*>", "_data[0]");
    r.symbol_length = offset(v, "Symbol", "_length");
    r.symbol_body = offset(v, "Symbol", "_body[0]");
    r.constant_pool_tags = offset(v, "ConstantPool", "_tags");
    r.constant_pool_length = offset(v, "ConstantPool", "_length");
    r.constant_pool_size = size(v, "ConstantPool");
    r.method_const_method = offset(v, "Method", "_constMethod");
    r.const_method_name_index = offset(v, "ConstMethod", "_name_index");
    r.const_method_signature_index = offset(v, "ConstMethod", "_signature_index");
    r.method_access_flags = offset(v, "Method", "_access_flags");
    r.method_counters = offset(v, "Method", "_method_counters");
    r.invocation_counter = offset(v, "MethodCounters", "_invocation_counter");
    r.counter_value = offset(v, "InvocationCounter", "_counter");
    r.method_size = size(v, "Method");
    r.const_method_size = size(v, "ConstMethod");
    r.const_method_code_size = offset(v, "ConstMethod", "_code_size");
    r.klass_name = offset(v, "Klass", "_name");
    r.instance_klass_constants = offset(v, "InstanceKlass", "_constants");
    r.instance_klass_init_state = offset(v, "InstanceKlass", "_init_state");
    r.instance_klass_methods = offset(v, "InstanceKlass", "_methods");
    return r;
}
} // namespace ocean::reconstructed::minecraft_hotspot_review
