#include "../../session/session_types.hpp"
#include <array>
#include <cstring>
#include <vector>
namespace ocean::reconstructed::minecraft_java_primitive_field_value {
// Recovered: decode JVM primitive field descriptors from little-endian bytes.
// Floating-point values remain raw IEEE bit patterns to preserve exact evidence.
using Bytes = std::vector<std::uint8_t>;
struct Value {                           // 112byte native record, not C++physicalABI
    ByteString state = "unknown";        // 0
    bool boolean = false;                // 16
    std::int64_t integer = 0;            // 24
    std::uint64_t floating_bits = 0;     // 32,32bitfloat bits zeroextended
    ByteString text;                     // 40,unusedbythisprimitivefunction
    Bytes raw56;                         // 56,remainingreferencepayloadreviewedseparately
    std::array<std::uint8_t, 8> raw80{}; // 80
    Bytes raw88;                         // 88,bytearraypayload(source188)
};
struct Contracts {
    virtual void original_bounds_panic() = 0;
};
std::uint64_t little_endian(const Bytes &bytes, std::size_t width) {
    std::uint64_t out = 0;
    for (std::size_t k = 0; k < width; ++k)
        out |= std::uint64_t{bytes[k]} << (k * 8);
    return out;
}
std::int64_t signed_integer(std::uint64_t bits, unsigned width) {
    if (width < 64 && (bits & (std::uint64_t{1} << (width - 1))))
        bits |= (~std::uint64_t{0}) << width;
    std::int64_t out;
    std::memcpy(&out, &bits, 8);
    return out; // capturedx64twoscomplement
}
Value decode(Contracts &rt, const ByteString &descriptor,
             const Bytes &bytes) { // hjkHr5RNrnIx@1a907a0
    Value out;
    if (descriptor.size() != 1)
        return out;
    const auto type = descriptor[0];
    std::size_t width = 0;
    switch (type) {
    case 'B':
    case 'Z':
        width = 1;
        break;
    case 'C':
    case 'S':
        width = 2;
        break;
    case 'I':
    case 'F':
        width = 4;
        break;
    case 'J':
    case 'D':
        width = 8;
        break;
    default:
        return out;
    }
    if (type == 'Z') {
        if (bytes.size() != 1 || bytes[0] > 1)
            return out; // invalidboolean quietunknown
        out.state = "value";
        out.boolean = bytes[0] != 0;
        return out;
    }
    if (bytes.size() < width) {
        rt.original_bounds_panic();
        return out;
    }
    const auto bits = little_endian(bytes, width);
    out.state = "value";
    if (type == 'F' || type == 'D')
        out.floating_bits = bits; // Preserve NaN payloads; do not convert to host numbers.
    else if (type == 'C')
        out.integer = static_cast<std::int64_t>(bits); // Unsigned UTF-16 unit; no validation.
    else
        out.integer = signed_integer(bits, static_cast<unsigned>(width * 8));
    return out; // Extra bytes are ignored for every type except boolean.
}
// Recovered: B/S/I/J are signed, C is unsigned, F/D preserve raw bits, and Z
// accepts only exactly one byte containing 0 or 1. Short buffers take the original
// bounds-panic path; invalid descriptors and booleans quietly remain unknown.
// Recovered ABI evidence identifies the full 112-byte value record.
} // namespace ocean::reconstructed::minecraft_java_primitive_field_value
