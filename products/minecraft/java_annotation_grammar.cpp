#include "../../session/session_types.hpp"
#include <optional>
#include <vector>

namespace ocean::reconstructed::minecraft_java_annotations {
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;

struct Text {
    ByteString value;
    bool valid = false;
};
struct Constant {
    ByteString kind;
    ByteString text;
    bool valid = false;
};
struct Blob {
    Bytes bytes;
    bool valid = false;
    bool unsupported = false;
};
struct Stats {
    std::uint32_t errors = 0;
    std::uint32_t unsupported = 0;
};
struct Pair {
    ByteString name;
    ByteString value;
};
struct Annotation {
    ByteString type;
    std::vector<Pair> pairs;
    ByteString target;
    Bytes raw;
    std::uint32_t errors = 0;
};
struct Parsed {
    Annotation annotation;
    bool complete = false;
};
struct Collection {
    std::vector<Annotation> annotations;
    std::uint32_t errors = 0;
};

struct Contracts {
    virtual Text pool_utf8(Address pool, std::uint16_t) = 0; // fmPh/source163
    virtual Constant pool_constant(Address pool, std::uint16_t) = 0; // fE/source164
    virtual std::optional<std::uint8_t> pool_tag(Address pool, std::uint16_t) = 0;
    virtual ByteString quote(ByteString) = 0; // cW0sCazLjq3
    virtual Blob stable_annotation_bytes(Address reader, Address array) = 0; // source167
    virtual void append_evidence(const Bytes&) = 0; // nzQt/source158
};

struct U16 {
    std::uint16_t value = 0;
    bool valid = false;
};

struct Cursor {
    const Bytes& bytes;
    std::size_t position = 0;
    Address pool = 0;
    std::uint32_t errors = 0;

    U16 read_u16_big_endian() {
        if (position > bytes.size() || bytes.size() - position < 2) return {};
        const auto value = std::uint16_t(
            (std::uint16_t(bytes[position]) << 8) | bytes[position + 1]);
        position += 2;
        return {value, true};
    }
};

ByteString decimal(std::uint64_t value) {
    return std::to_string(value);
}

ByteString hexadecimal(const Bytes& bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    ByteString result;
    for (const auto byte : bytes) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

Text utf8(Contracts& runtime, const Cursor& cursor, std::uint16_t index) {
    return cursor.pool != 0 ? runtime.pool_utf8(cursor.pool, index) : Text{};
}

ByteString join(const std::vector<ByteString>& values) {
    ByteString result;
    bool first = true;
    for (const auto& value : values) {
        if (!first) result += ',';
        first = false;
        result += value;
    }
    return result;
}

Text parse_element_value(Contracts&, Cursor&, std::int64_t depth);

Parsed parse_annotation(
    Contracts& runtime,
    Cursor& cursor,
    std::int64_t depth,
    ByteString target) { // qsXi03@1a30020
    if (depth > 32) return {};

    const auto start = cursor.position;
    const auto type_index = cursor.read_u16_big_endian();
    if (!type_index.valid) return {};

    const auto type = utf8(runtime, cursor, type_index.value);
    const auto pair_count = cursor.read_u16_big_endian();
    if (!pair_count.valid || pair_count.value > 16384) return {};

    Annotation result;
    result.type = type.value;
    result.target = std::move(target);
    if (!type.valid) {
        ++result.errors;
        ++cursor.errors;
    }

    for (std::uint32_t index = 0; index < pair_count.value; ++index) {
        const auto name_index = cursor.read_u16_big_endian();
        if (!name_index.valid) return {}; // Discard this partial annotation.

        const auto name = utf8(runtime, cursor, name_index.value);
        const auto value = parse_element_value(runtime, cursor, depth + 1);
        if (!name.valid || !value.valid) {
            ++result.errors;
            ++cursor.errors;
        }
        // Recovered: invalid lookup text is retained in the parsed record.
        result.pairs.push_back({name.value, value.value});
    }

    result.raw = Bytes(
        cursor.bytes.begin() + start,
        cursor.bytes.begin() + cursor.position);
    return {result, true};
}

ByteString render(Contracts& runtime, const Annotation& annotation) { // oaa8SaP@1a31860
    std::vector<ByteString> pairs;
    for (const auto& pair : annotation.pairs)
        pairs.push_back(runtime.quote(pair.name) + "=" + pair.value);
    return "@" + annotation.type + "(" + join(pairs) + ")";
}

void append_evidence(
    Contracts& runtime,
    const ByteString& label,
    const std::vector<Annotation>& annotations) { // wFn@1a3a700
    for (const auto& annotation : annotations) {
        runtime.append_evidence(annotation.raw);
        const auto text =
            label + ":" + annotation.target + ":" + render(runtime, annotation);
        runtime.append_evidence(Bytes{text.begin(), text.end()});
    }
}

Text parse_element_value(
    Contracts& runtime,
    Cursor& cursor,
    std::int64_t depth) { // tVOM@1a305a0
    if (depth > 32 || cursor.position >= cursor.bytes.size()) return {};

    const auto tag = cursor.bytes[cursor.position++];
    if (tag == '@') {
        const auto nested = parse_annotation(runtime, cursor, depth + 1, {});
        return {render(runtime, nested.annotation), nested.complete};
    }
    if (tag == '[') {
        const auto count = cursor.read_u16_big_endian();
        if (!count.valid || count.value > 16384) return {};

        std::vector<ByteString> values;
        bool valid = true;
        for (std::uint32_t index = 0; index < count.value; ++index) {
            const auto child = parse_element_value(runtime, cursor, depth + 1);
            values.push_back(child.value);
            valid = valid && child.valid;
        }
        return {"[" + join(values) + "]", valid};
    }
    if (tag == 's' || tag == 'c') {
        const auto index = cursor.read_u16_big_endian();
        const auto value = utf8(runtime, cursor, index.value);
        const ByteString prefix = tag == 's' ? "s(" : "class(";
        return {prefix + runtime.quote(value.value) + ")", index.valid && value.valid};
    }
    if (tag == 'e') {
        const auto type_index = cursor.read_u16_big_endian();
        const auto name_index = cursor.read_u16_big_endian();
        const auto type = utf8(runtime, cursor, type_index.value);
        const auto name = utf8(runtime, cursor, name_index.value);
        return {"enum(" + runtime.quote(type.value) + "." +
                    runtime.quote(name.value) + ")",
                type_index.valid && name_index.valid && type.valid && name.valid};
    }

    std::uint8_t expected_pool_tag = 0;
    switch (tag) {
    case 'B':
    case 'C':
    case 'I':
    case 'S':
    case 'Z': expected_pool_tag = 3; break;
    case 'D': expected_pool_tag = 6; break;
    case 'F': expected_pool_tag = 4; break;
    case 'J': expected_pool_tag = 5; break;
    }

    if (expected_pool_tag != 0) {
        const auto index = cursor.read_u16_big_endian();
        if (!index.valid || cursor.pool == 0) return {};

        const auto constant = runtime.pool_constant(cursor.pool, index.value);
        const auto actual_tag = constant.valid ?
            runtime.pool_tag(cursor.pool, index.value) :
            std::optional<std::uint8_t>{};
        const ByteString type_letter(1, char(tag));
        if (!constant.valid || !actual_tag || *actual_tag != expected_pool_tag)
            return {type_letter + "#" + decimal(index.value), false};
        return {type_letter + "(" + constant.kind + ":" + constant.text + ")", true};
    }

    return {"tag(0x" + hexadecimal(Bytes{tag}) + ")", false};
}

Text parse_type_target(Cursor& cursor) { // cBIL@1a32cc0
    if (cursor.position >= cursor.bytes.size()) return {};

    const auto target_tag = cursor.bytes[cursor.position++];
    const auto body_start = cursor.position;
    if (target_tag == 0 || target_tag == 1 || target_tag == 0x16)
        cursor.position = body_start + 1;
    else if (target_tag == 0x10 || target_tag == 0x11 || target_tag == 0x12 ||
             target_tag == 0x17 || (target_tag >= 0x42 && target_tag <= 0x46))
        cursor.position = body_start + 2;
    else if (target_tag >= 0x13 && target_tag <= 0x15) {
        // Empty target payload.
    } else if (target_tag >= 0x47 && target_tag <= 0x4b)
        cursor.position = body_start + 3;
    else if (target_tag == 0x40 || target_tag == 0x41) {
        const auto table_length = cursor.read_u16_big_endian();
        if (!table_length.valid || table_length.value > 16384) return {};
        cursor.position += std::size_t{table_length.value} * 6;
    } else {
        return {};
    }

    // Recovered: fixed/local target truncation first advances beyond the input,
    // then fails here.
    if (cursor.position > cursor.bytes.size()) return {};
    return {"0x" + hexadecimal(Bytes{target_tag}) + ":" +
                hexadecimal(Bytes(cursor.bytes.begin() + body_start,
                                  cursor.bytes.begin() + cursor.position)),
            true};
}

Collection parse_ordinary(
    Contracts& runtime,
    const Bytes& bytes,
    Address pool) { // ox7@1a31ac0
    Cursor cursor{bytes, 0, pool};
    Collection result;
    const auto count = cursor.read_u16_big_endian();
    if (!count.valid || count.value > 16384) return {{}, 1};

    for (std::uint32_t index = 0; index < count.value; ++index) {
        const auto record = parse_annotation(runtime, cursor, 0, {});
        if (!record.complete) {
            result.errors = cursor.errors + 1;
            return result;
        }
        result.annotations.push_back(record.annotation);
    }
    result.errors = cursor.errors + std::uint32_t(cursor.position != bytes.size());
    return result;
}

Collection parse_parameters(
    Contracts& runtime,
    const Bytes& bytes,
    Address pool) { // dw0@1a31e20
    if (bytes.empty()) return {{}, 1};

    Cursor cursor{bytes, 1, pool};
    Collection result;
    const auto parameter_count = bytes[0];
    for (std::uint32_t parameter = 0; parameter < parameter_count; ++parameter) {
        const auto count = cursor.read_u16_big_endian();
        if (!count.valid || count.value > 16384) {
            result.errors = cursor.errors + 1;
            return result;
        }
        for (std::uint32_t index = 0; index < count.value; ++index) {
            const auto record = parse_annotation(
                runtime, cursor, 0, "parameter:" + decimal(parameter));
            if (!record.complete) {
                result.errors = cursor.errors + 1;
                return result;
            }
            result.annotations.push_back(record.annotation);
        }
    }
    result.errors = cursor.errors + std::uint32_t(cursor.position != bytes.size());
    return result;
}

Collection parse_types(
    Contracts& runtime,
    const Bytes& bytes,
    Address pool) { // nOG@1a326e0
    Cursor cursor{bytes, 0, pool};
    Collection result;
    const auto count = cursor.read_u16_big_endian();
    if (!count.valid || count.value > 16384) return {{}, 1};

    for (std::uint32_t index = 0; index < count.value; ++index) {
        auto target = parse_type_target(cursor);
        if (!target.valid || cursor.position >= bytes.size()) {
            result.errors = cursor.errors + 1;
            return result;
        }

        const auto path_byte_count = std::size_t{bytes[cursor.position++]} * 2;
        if (path_byte_count > bytes.size() - cursor.position) {
            result.errors = cursor.errors + 1;
            return result;
        }
        if (path_byte_count != 0) {
            target.value += ":path=" + hexadecimal(Bytes(
                bytes.begin() + cursor.position,
                bytes.begin() + cursor.position + path_byte_count));
        }
        cursor.position += path_byte_count;

        const auto record = parse_annotation(runtime, cursor, 0, target.value);
        if (!record.complete) {
            result.errors = cursor.errors + 1;
            return result;
        }
        result.annotations.push_back(record.annotation);
    }
    result.errors = cursor.errors + std::uint32_t(cursor.position != bytes.size());
    return result;
}

std::vector<Annotation> read_attribute(
    Contracts& runtime,
    Address reader,
    Address array,
    Address pool,
    const ByteString& label,
    Stats& stats) { // efRe@1a333e0
    const auto blob = runtime.stable_annotation_bytes(reader, array);
    if (blob.unsupported) {
        ++stats.unsupported;
        return {};
    }
    if (!blob.valid) {
        if (array != 0) ++stats.errors;
        return {};
    }

    Collection parsed;
    if (label == "annotations")
        parsed = parse_ordinary(runtime, blob.bytes, pool);
    else if (label == "parameters")
        parsed = parse_parameters(runtime, blob.bytes, pool);
    else if (label == "type")
        parsed = parse_types(runtime, blob.bytes, pool);
    else
        parsed.errors = 1;

    stats.errors += parsed.errors;
    return parsed.annotations;
}

// Recovered: this is the JVM annotation grammar used for class, field, method,
// parameter, type, and default-value metadata. It limits nesting to 32 and list
// sizes to 16,384. Completion is independent of semantic lookup errors: invalid
// names/constants can remain in a completed annotation and still be emitted.
// Evidence consists of the original raw bytes followed by
// `<label>:<target>:@<type>(<pairs>)`; parse errors do not suppress completed
// records. Type-path component contents are copied without semantic validation.
//
// Interpretation: annotations are general Java metadata collected before SDK
// rules. An `aero` UTF-8 string in a fixture is not a dedicated Aero detector.
// The native stable-array reader and ConstMethod traversal remain providers.
// This readable reconstruction was never compiled or executed.
}
