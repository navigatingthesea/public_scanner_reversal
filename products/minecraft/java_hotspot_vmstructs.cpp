#include "java_hotspot_vmstructs.hpp"
#include <cstring>
namespace ocean::reconstructed::minecraft_hotspot_review {
// Recovered: load the target's mapped jvm.dll, resolve HotSpot's exported
// metadata tables, and materialize the offsets, types, addresses, sizes, and
// constants used by every later native-memory collector.
//
// The six required exports are three table pointers and their three strides.
// This is the recovered "six" associated with VMStruct parsing; it is not a
// six-class Aero watch list.  VMLongConstants and its stride are optional.
std::size_t FieldKeyHash::operator()(const FieldKey &k) const {
    return std::hash<ByteString>{}(k.type) ^ (std::hash<ByteString>{}(k.field) << 1);
}
static Word read_u64_from_row(const std::vector<std::uint8_t> &b, std::size_t at) {
    Word v = 0;
    if (at + 8 <= b.size())
        std::memcpy(&v, b.data() + at, 8);
    return v;
}
static std::uint32_t read_u32_from_row(const std::vector<std::uint8_t> &b, std::size_t at) {
    std::uint32_t v = 0;
    if (at + 4 <= b.size())
        std::memcpy(&v, b.data() + at, 4);
    return v;
}
static Result<ByteString> read_remote_text(Contracts &c, Word p) { return c.read_c_string(p); }
static std::optional<Word> exported_pointer(Contracts &c, const Module &m,
                                            const std::unordered_map<ByteString, Word> &e,
                                            const ByteString &name, Error &error) {
    auto it = e.find(name);
    if (it == e.end()) {
        error = c.format_error("missing jvm.dll export %s", name);
        return std::nullopt;
    }
    auto value = c.read_u64(m.base + it->second);
    if (value.error.present()) {
        error = value.error;
        return std::nullopt;
    }
    return value.value;
}
// scygy4g@1aa8580. The original reads the complete mapped jvm.dll image and
// accepts it only when the returned byte count equals Module::size.
Result<VmLayout> load_vmstructs(Contracts &c, const Module &module) {
    auto image = c.read_remote(module.base, module.size);
    if (image.error.present() || image.value.size() != module.size)
        return {{},
                image.error.present() ? image.error : c.error_string("cannot read mapped jvm.dll")};
    auto parsed = c.parse_pe_exports(image.value);
    if (parsed.error.present())
        return {{}, parsed.error};
    const auto &exports = parsed.value;
    Error error;
    auto structs = exported_pointer(c, module, exports, "gHotSpotVMStructs", error);
    if (!structs)
        return {{}, error};
    auto struct_stride =
        exported_pointer(c, module, exports, "gHotSpotVMStructEntryArrayStride", error);
    if (!struct_stride)
        return {{}, error};
    auto types = exported_pointer(c, module, exports, "gHotSpotVMTypes", error);
    if (!types)
        return {{}, error};
    auto type_stride =
        exported_pointer(c, module, exports, "gHotSpotVMTypeEntryArrayStride", error);
    if (!type_stride)
        return {{}, error};
    auto ints = exported_pointer(c, module, exports, "gHotSpotVMIntConstants", error);
    if (!ints)
        return {{}, error};
    auto int_stride =
        exported_pointer(c, module, exports, "gHotSpotVMIntConstantEntryArrayStride", error);
    if (!int_stride)
        return {{}, error};
    VmLayout out;
    // Recovered: all four metadata loops cap the row count at 250,000 and stop on a null name
    // pointer.
    for (Word i = 0; i < 250000; i++) {
        auto row = c.read_remote(*structs + i * *struct_stride, *struct_stride);
        if (row.error.present())
            return {{}, row.error};
        if (row.value.size() < 48)
            return {{}, c.error_string("cannot read HotSpot VMStruct entry")};
        const Word type_name = read_u64_from_row(row.value, 0);
        if (!type_name)
            break;
        const Word field_name = read_u64_from_row(row.value, 8);
        if (!field_name)
            continue;
        auto type = read_remote_text(c, type_name);
        if (type.error.present())
            return {{}, type.error};
        auto field = read_remote_text(c, field_name);
        if (field.error.present())
            return {{}, field.error};
        FieldKey key{type.value, field.value};
        if (read_u32_from_row(row.value, 24) != 0) {
            out.static_addresses[key] = read_u64_from_row(row.value, 40);
            continue;
        }
        out.instance_offsets[key] = read_u64_from_row(row.value, 32);
        const Word type_string = read_u64_from_row(row.value, 16);
        if (type_string) {
            auto value = read_remote_text(c, type_string);
            if (value.error.present())
                return {{}, value.error};
            out.field_types[key] = value.value;
        }
    }
    for (Word i = 0; i < 250000; i++) {
        auto row = c.read_remote(*types + i * *type_stride, *type_stride);
        if (row.error.present())
            return {{}, row.error};
        if (row.value.size() < 40)
            return {{}, c.error_string("cannot read HotSpot VMType entry")};
        const Word name = read_u64_from_row(row.value, 0);
        if (!name)
            break;
        auto value = read_remote_text(c, name);
        if (value.error.present())
            return {{}, value.error};
        out.type_sizes[value.value] = read_u64_from_row(row.value, 32);
    }
    for (Word i = 0; i < 250000; i++) {
        auto row = c.read_remote(*ints + i * *int_stride, *int_stride);
        if (row.error.present())
            return {{}, row.error};
        if (row.value.size() < 12)
            return {{}, c.error_string("cannot read HotSpot VMIntConstant entry")};
        const Word name = read_u64_from_row(row.value, 0);
        if (!name)
            break;
        auto value = read_remote_text(c, name);
        if (value.error.present())
            return {{}, value.error};
        const auto signed_value = static_cast<std::int32_t>(read_u32_from_row(row.value, 8));
        out.constants[value.value] = static_cast<Word>(static_cast<std::int64_t>(signed_value));
    }
    // The VMLongConstants pair is optional. If either export is absent the original skips this
    // table.
    auto long_table = exports.find("gHotSpotVMLongConstants"),
         long_stride_export = exports.find("gHotSpotVMLongConstantEntryArrayStride");
    if (long_table != exports.end() && long_stride_export != exports.end()) {
        auto table = c.read_u64(module.base + long_table->second),
             stride = c.read_u64(module.base + long_stride_export->second);
        if (table.error.present())
            return {{}, table.error};
        if (stride.error.present())
            return {{}, stride.error};
        for (Word i = 0; i < 250000; i++) {
            auto row = c.read_remote(table.value + i * stride.value, stride.value);
            if (row.error.present())
                return {{}, row.error};
            if (row.value.size() < 16)
                return {{}, c.error_string("cannot read HotSpot VMLongConstant entry")};
            const Word name = read_u64_from_row(row.value, 0);
            if (!name)
                break;
            auto value = read_remote_text(c, name);
            if (value.error.present())
                return {{}, value.error};
            out.constants[value.value] = read_u64_from_row(row.value, 8);
        }
    }
    if (out.instance_offsets.empty() && out.field_types.empty() && out.static_addresses.empty() &&
        out.type_sizes.empty() && out.constants.empty())
        return {{}, c.error_string("HotSpot metadata tables contain no usable entries")};
    const FieldKey head{"ClassLoaderDataGraph", "_head"}, next{"ClassLoaderData", "_next"},
        klasses{"ClassLoaderData", "_klasses"}, next_link{"Klass", "_next_link"};
    auto h = out.static_addresses.find(head), n = out.instance_offsets.find(next),
         k = out.instance_offsets.find(klasses), l = out.instance_offsets.find(next_link);
    if (h != out.static_addresses.end() && n != out.instance_offsets.end() &&
        k != out.instance_offsets.end() && l != out.instance_offsets.end())
        out.class_registry = {h->second, n->second, k->second, l->second, true, false};
    else if (c.discover_class_registry_fallback(out, module)) {
        out.class_registry.valid = true;
        out.class_registry.discovered_by_fallback = true;
    } else
        return {{}, c.error_string("HotSpot class registry layout is unavailable")};
    return {std::move(out), {}};
}
} // namespace ocean::reconstructed::minecraft_hotspot_review
