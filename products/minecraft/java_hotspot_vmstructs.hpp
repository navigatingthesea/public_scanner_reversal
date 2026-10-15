#pragma once
#include "../../session/session_types.hpp"
#include <array>
#include <optional>
#include <string>
#include <unordered_map>
namespace ocean::reconstructed::minecraft_hotspot_review {
// Recovered: these containers mirror the VMStruct, VMType, and VM constant
// tables read from the target JVM.  They describe layout only; they do not
// perform process-memory reads by themselves.
//
// Interpretation: NativeJavaReader is the metadata/caching state shared by the
// later class, symbol, constant-pool, and method readers.
//
// Unresolved: the implementation of the class-registry fallback remains a
// provider boundary because its producing body was not recovered here.
using Word = std::uint64_t;
struct Error {
    Word type = 0, data = 0;
    bool present() const { return type != 0; }
};
template <class T> struct Result {
    T value{};
    Error error{};
};
struct Module {
    Word base = 0, size = 0;
    ByteString path;
};
struct FieldKey {
    ByteString type, field;
    bool operator==(const FieldKey &) const = default;
};
struct FieldKeyHash {
    std::size_t operator()(const FieldKey &k) const;
};
struct ClassRegistryLayout {
    Word head_address = 0, next_offset = 0, klasses_offset = 0, next_link_offset = 0;
    bool valid = false;
    bool discovered_by_fallback = false;
};
struct VmLayout {
    std::unordered_map<FieldKey, Word, FieldKeyHash> instance_offsets;
    std::unordered_map<FieldKey, ByteString, FieldKeyHash> field_types;
    std::unordered_map<FieldKey, Word, FieldKeyHash> static_addresses;
    std::unordered_map<ByteString, Word> type_sizes;
    std::unordered_map<ByteString, Word> constants; // bothVMIntConstantsandVMLongConstants
    ClassRegistryLayout class_registry;
};
struct Contracts {
    virtual Result<std::vector<std::uint8_t>> read_remote(Word address, Word size) = 0;
    virtual Result<Word> read_u64(Word address) = 0;
    virtual Result<ByteString> read_c_string(Word address) = 0;
    virtual Result<std::unordered_map<ByteString, Word>>
    parse_pe_exports(const std::vector<std::uint8_t> &mapped_image) = 0;
    virtual bool discover_class_registry_fallback(VmLayout &, const Module &) = 0;
    virtual Error error_string(const ByteString &) = 0;
    virtual Error format_error(const ByteString &, const ByteString &) = 0;
};
Result<VmLayout> load_vmstructs(Contracts &, const Module &);
struct ReaderBinding {
    std::optional<Word> value;
};
struct NativeJavaReader {
    Word context = 0;
    const VmLayout *layout = nullptr;
    std::unordered_map<Word, Word> class_cache;
    std::unordered_map<Word, ByteString> symbol_cache;
    Word instance_klass_loaded = 0;
    ReaderBinding array_klass_length, array_klass_data, array_u1_data;
    ReaderBinding symbol_length, symbol_body;
    ReaderBinding constant_pool_tags, constant_pool_length, constant_pool_size;
    ReaderBinding method_const_method, const_method_name_index, const_method_signature_index;
    ReaderBinding method_access_flags, method_counters, invocation_counter, counter_value;
    ReaderBinding method_size, const_method_size, const_method_code_size;
    ReaderBinding klass_name, instance_klass_constants, instance_klass_init_state,
        instance_klass_methods;
};
NativeJavaReader build_native_java_reader(Word context, const VmLayout &);
} // namespace ocean::reconstructed::minecraft_hotspot_review
