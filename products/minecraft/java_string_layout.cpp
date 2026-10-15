#include "../../session/session_types.hpp"
#include <vector>
namespace ocean::reconstructed::minecraft_java_string_layout {
// Recovered: derive java.lang.String's compact-string value/coder offsets from
// the first bootstrap String class record. This avoids hard-coding a JDK layout.
struct Field {
    ByteString name, descriptor;
    std::uint32_t offset = 0;
    bool offset_valid = false;
    std::uint32_t access = 0;
};
struct Class {
    ByteString name;
    std::uint8_t context_flag = 0;
    std::vector<Field> fields;
};
struct Layout {
    std::uint32_t value_offset = 0, coder_offset = 0;
    bool available = false;
};
Layout from_classes(const std::vector<Class> &classes) { // o4jgsQdUKbq@1a8e9c0
    for (const auto &klass : classes) {
        if (klass.name != "java.lang.String" || klass.context_flag == 0)
            continue;
        Layout out;
        bool have_value = false, have_coder = false;
        for (const auto &field : klass.fields) {
            if ((field.access & 8) || !field.offset_valid)
                continue;
            if (field.name == "value" && field.descriptor == "[B") {
                out.value_offset = field.offset;
                have_value = true;
            } else if (field.name == "coder" && field.descriptor == "B") {
                out.coder_offset = field.offset;
                have_coder = true;
            }
        }
        out.available = have_value && have_coder;
        return out;
        // Recovered: the first matching bootstrap String class decides, even when
        // it lacks usable fields. The last matching field of each kind wins.
    }
    return {};
}
// Recovered: field names and descriptors are case-sensitive; static or invalid-
// offset fields are ignored; duplicate matches use the last value; and zero or
// UINT32_MAX offsets are accepted. This layout is derived from collected class
// records rather than an assumed JDK version.
} // namespace ocean::reconstructed::minecraft_java_string_layout
