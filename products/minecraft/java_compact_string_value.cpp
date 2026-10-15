#include "../../session/session_types.hpp"
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_compact_string_value {
// Recovered: read java.lang.String.coder and its byte[] backing value with
// stability checks, then convert Latin-1 or UTF-16LE content to UTF-8 text.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
template <class T> struct Read {
    T value;
    bool error = false;
};
template <class T> struct Valid {
    T value;
    bool valid = false;
};
struct Reference {
    Address object = 0, raw = 0;
    bool valid = false, is_null = false;
};
struct ArrayValue {
    ByteString state = "unknown";
    Bytes bytes;
}; // 188
struct Layout {
    Address value_offset = 0, coder_offset = 0;
    bool available = false;
}; // o4jgsQdUKbq
struct Value { // native112: state0,text40,raw56,coder80,zeros88
    ByteString state = "unknown", text;
    Bytes raw;
    std::uint8_t coder = 0;
};
void append_utf8(ByteString &out, std::uint32_t rune) {
    if (rune <= 0x7f)
        out.push_back(static_cast<char>(rune));
    else if (rune <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (rune >> 6)));
        out.push_back(static_cast<char>(0x80 | (rune & 63)));
    } else if (rune <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (rune >> 12)));
        out.push_back(static_cast<char>(0x80 | ((rune >> 6) & 63)));
        out.push_back(static_cast<char>(0x80 | (rune & 63)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (rune >> 18)));
        out.push_back(static_cast<char>(0x80 | ((rune >> 12) & 63)));
        out.push_back(static_cast<char>(0x80 | ((rune >> 6) & 63)));
        out.push_back(static_cast<char>(0x80 | (rune & 63)));
    }
}
std::optional<ByteString> decode(const Bytes &raw, std::uint8_t coder) { // gFgOzaFOjh@1a91e00
    ByteString out;
    if (coder == 0) {
        for (const auto byte : raw)
            append_utf8(out, byte);
        return out;
    } // Latin1byte=>rune,notUTF8input
    if (coder != 1 || raw.size() % 2)
        return std::nullopt;
    const auto unit = [&](std::size_t at) {
        return std::uint32_t{raw[at]} | (std::uint32_t{raw[at + 1]} << 8);
    };
    for (std::size_t k = 0; k < raw.size(); k += 2) {
        auto rune = unit(k);
        if (rune >= 0xd800 && rune <= 0xdbff) {
            if (k + 2 < raw.size()) {
                const auto low = unit(k + 2);
                if (low >= 0xdc00 && low <= 0xdfff) {
                    rune = 0x10000 + ((rune - 0xd800) << 10) + (low - 0xdc00);
                    k += 2;
                } else
                    rune = 0xfffd;
            } else
                rune = 0xfffd;
        } else if (rune >= 0xdc00 && rune <= 0xdfff)
            rune = 0xfffd;
        append_utf8(out, rune);
    }
    return out; // emptyvalid;unpairedsurrogatesreplacement;BOMkept
}
template <class RuntimeContext> struct Contracts {
    virtual bool object_class_validation_available(RuntimeContext &) = 0;
    virtual Valid<ByteString> object_class_name(RuntimeContext &, Address) = 0;
    virtual Read<Bytes> exact_read(Address reader, Address, std::size_t) = 0;
    virtual Reference stable_reference(RuntimeContext &, Address slot) = 0;                   // 187
    virtual ArrayValue read_byte_array(Address reader, RuntimeContext &, Address object) = 0; // 188
    virtual bool reference_still_matches(RuntimeContext &, Address slot, Address raw) = 0;    // 187
    virtual void original_bounds_panic() = 0;
};
template <class RuntimeContext>
Value collect(Contracts<RuntimeContext> &rt, Address reader, RuntimeContext &context,
              Address object, const Layout &layout) { // xoBFxvoqU@1a917a0
    if (!layout.available)
        return {};
    if (rt.object_class_validation_available(context)) {
        const auto name = rt.object_class_name(context, object);
        if (!name.valid || name.value != "java.lang.String")
            return {};
    }
    const Address coder_address = object + layout.coder_offset;
    const auto first = rt.exact_read(reader, coder_address, 1);
    const auto second = rt.exact_read(reader, coder_address, 1); // evenfirsterror
    if (first.error || second.error || first.value != second.value)
        return {};
    if (first.value.empty()) {
        rt.original_bounds_panic();
        return {};
    }
    const auto coder = first.value[0];
    if (coder > 1)
        return {};
    const Address value_slot = object + layout.value_offset;
    const auto reference = rt.stable_reference(context, value_slot);
    if (!reference.valid || reference.is_null)
        return {};
    const auto bytes = rt.read_byte_array(reader, context, reference.object);
    if (bytes.state != "value" && bytes.state != "truncated")
        return {};
    const auto last = rt.exact_read(reader, coder_address, 1);
    if (last.error)
        return {};
    if (last.value.empty()) {
        rt.original_bounds_panic();
        return {};
    }
    if (last.value[0] != coder || !rt.reference_still_matches(context, value_slot, reference.raw))
        return {};
    const auto text = decode(bytes.bytes, coder);
    if (!text)
        return {};
    // The String value keeps its raw backing bytes in the recovered value slot;
    // it does not append a second byte-array payload.
    return {bytes.state, *text, bytes.bytes, coder};
}
// Recovered: paths cover all coder/layout/reference gates, truncation, every
// Latin-1 byte, UTF-16 surrogate pairs and replacements, BOM preservation, empty
// input, and rejected odd-length UTF-16. The "Aero" string used during validation
// was arbitrary fixture data, not a recovered detector signature.
} // namespace ocean::reconstructed::minecraft_java_compact_string_value
