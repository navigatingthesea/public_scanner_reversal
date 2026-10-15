#include "../../session/session_types.hpp"
#include <iomanip>
#include <sstream>
#include <vector>

namespace ocean::reconstructed::minecraft_java_field_value_evidence {
using Bytes = std::vector<std::uint8_t>;

// Logical view of the recovered 112-byte Go value record.
struct Value {
    ByteString state = "unknown";
    bool boolean = false;
    std::int64_t integer = 0;
    std::uint64_t floating_bits = 0;
    ByteString text;
    Bytes string_bytes;
    std::uint8_t coder = 0;
    Bytes array_bytes;
};

struct Field {
    ByteString name;
    ByteString descriptor;
    const Value* value = nullptr;
};

struct Sink { // nzQtDj8Ji/source158
    virtual void append(const ByteString&) = 0;
    virtual void append(const Bytes&) = 0;
};

Bytes little_endian(std::uint64_t value, std::size_t width) {
    Bytes bytes(width);
    for (std::size_t index = 0; index < width; ++index)
        bytes[index] = static_cast<std::uint8_t>(value >> (index * 8));
    return bytes;
}

ByteString hexadecimal_bits(std::uint64_t value, unsigned width) {
    std::ostringstream text;
    text << "0x" << std::uppercase << std::hex << std::setfill('0')
         << std::setw(width) << value;
    return text.str();
}

void append(
    Sink& sink,
    const ByteString& class_name,
    const Field& field) { // ewpWZVV@1a8e140
    if (field.value == nullptr) return;
    const auto& value = *field.value;

    // Recovered: this header is always emitted for a present value record and
    // uses raw strings without quoting.
    sink.append("STATIC:" + class_name + ":" + field.name + ":" +
                field.descriptor + ":" + value.state);
    if (value.state != "value" && value.state != "truncated") return;

    const auto& descriptor = field.descriptor;
    if (descriptor.size() == 1) {
        std::size_t integer_width = 0;
        switch (descriptor[0]) {
        case 'B': integer_width = 1; break;
        case 'C':
        case 'S': integer_width = 2; break;
        case 'I': integer_width = 4; break;
        case 'J': integer_width = 8; break;
        case 'F': {
            const auto bits = static_cast<std::uint32_t>(value.floating_bits);
            sink.append(little_endian(bits, 4));
            sink.append(hexadecimal_bits(bits, 8));
            return;
        }
        case 'D':
            sink.append(little_endian(value.floating_bits, 8));
            sink.append(hexadecimal_bits(value.floating_bits, 16));
            return;
        case 'Z':
            sink.append(ByteString{value.boolean ? "true" : "false"});
            sink.append(Bytes{static_cast<std::uint8_t>(value.boolean)});
            return;
        }

        if (integer_width != 0) {
            sink.append(little_endian(
                static_cast<std::uint64_t>(value.integer), integer_width));
            sink.append(std::to_string(value.integer));
            return;
        }
    }

    if (descriptor == "[B") {
        sink.append(value.array_bytes);
        return;
    }
    if (descriptor == "Ljava/lang/String;") {
        sink.append(value.text);
        sink.append(value.string_bytes);
    }
}

// Recovered evidence encoding:
// - integer primitives: little-endian bytes, then signed decimal text;
// - float/double: raw little-endian bits, then uppercase hexadecimal bits;
// - boolean: text first, then one binary byte;
// - byte array: raw bytes;
// - String: decoded text first, then backing bytes.
// Unknown/null values emit only the header. `truncated` values still emit their
// available payload. Unsupported descriptors also keep only the header. The
// sink ignores empty appends, inserts its own zero separators, and enforces the
// shared budget. Twenty original routes were checked. This readable source was
// never compiled or executed.
}
