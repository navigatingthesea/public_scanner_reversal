#include "../../session/session_types.hpp"
#include <bit>
#include <vector>

namespace ocean::reconstructed::minecraft_java_pool_constant_renderer {
using Bytes = std::vector<std::uint8_t>;

struct Pool {
    Bytes tags;
    Bytes entries;
};
struct Text {
    ByteString value;
    bool valid;
};
struct Pair {
    ByteString name;
    ByteString descriptor;
    bool valid;
};
struct Member {
    ByteString kind;
    ByteString owner;
    ByteString name;
    ByteString descriptor;
    bool valid;
};
struct Representation {
    ByteString kind;
    ByteString text;
    bool valid;
};

struct Contracts {
    virtual Text reviewed_utf8(const Pool&, std::uint16_t) = 0;
    virtual Text reviewed_class_name(const Pool&, std::uint16_t) = 0;
    virtual Pair reviewed_name_type(const Pool&, std::uint16_t) = 0;
    virtual Member reviewed_member(const Pool&, std::uint16_t) = 0;
    virtual Text original_string_callback_at_pool56(std::uint64_t symbol_address) = 0;
    virtual ByteString original_quote_to_ascii(const ByteString&) = 0;
};

std::uint64_t little_endian_word(
    const Pool& pool,
    std::uint16_t index,
    std::size_t size) {
    std::uint64_t result = 0;
    const auto offset = std::size_t{index} * 8;
    for (std::size_t byte = 0; byte < size; ++byte)
        result |= std::uint64_t{pool.entries[offset + byte]} << (8 * byte);
    return result;
}

ByteString fixed_width_hex(std::uint64_t value, std::size_t digits) {
    static constexpr char hex[] = "0123456789ABCDEF";
    ByteString result(digits, '0');
    for (std::size_t cursor = digits; cursor > 0;) {
        result[--cursor] = hex[value & 15];
        value >>= 4;
    }
    return "0x" + result;
}

ByteString member_text(Contracts& runtime, const Member& member) {
    return runtime.original_quote_to_ascii(member.owner) + "." +
        runtime.original_quote_to_ascii(member.name) + ":" +
        runtime.original_quote_to_ascii(member.descriptor);
}

Representation render(
    Contracts& runtime,
    const Pool* pool,
    std::uint16_t index) { // fEGlRI@1a4e200
    if (pool == nullptr || index == 0 || index >= pool->tags.size() ||
        pool->entries.size() != pool->tags.size() * 8)
        return {{}, {}, false};

    const auto tag = pool->tags[index];
    const auto encoded = static_cast<std::uint32_t>(
        little_endian_word(*pool, index, 4));

    if (tag == 1) {
        const auto value = runtime.reviewed_utf8(*pool, index);
        return {"Utf8", runtime.original_quote_to_ascii(value.value), value.valid};
    }
    if (tag == 3)
        return {"Integer", std::to_string(std::bit_cast<std::int32_t>(encoded)), true};
    if (tag == 4)
        return {"Float", fixed_width_hex(encoded, 8), true};
    if (tag == 5)
        return {"Long", fixed_width_hex(little_endian_word(*pool, index, 8), 16), true};
    if (tag == 6)
        return {"Double", fixed_width_hex(little_endian_word(*pool, index, 8), 16), true};

    if (tag == 7 || tag == 100 || tag == 103) {
        const auto value = runtime.reviewed_class_name(*pool, index);
        return {"Class", runtime.original_quote_to_ascii(value.value), value.valid};
    }
    if (tag == 8) {
        const auto value = runtime.original_string_callback_at_pool56(
            little_endian_word(*pool, index, 8));
        return {"String", runtime.original_quote_to_ascii(value.value), value.valid};
    }

    if (tag == 9 || tag == 10 || tag == 11) {
        const auto value = runtime.reviewed_member(*pool, index);
        if (!value.valid) return {{}, {}, false};
        const ByteString kind = tag == 9 ? "Fieldref" :
            tag == 10 ? "Methodref" : "InterfaceMethodref";
        return {kind, member_text(runtime, value), true};
    }

    if (tag == 12) {
        const auto value = runtime.reviewed_name_type(*pool, index);
        return {"NameAndType",
                runtime.original_quote_to_ascii(value.name) + ":" +
                    runtime.original_quote_to_ascii(value.descriptor),
                value.valid};
    }

    if (tag == 15) {
        const auto reference_kind = static_cast<std::uint16_t>(encoded);
        const auto target_index = static_cast<std::uint16_t>(encoded >> 16);
        if (reference_kind == 0 || reference_kind > 9 || target_index == 0 ||
            target_index >= pool->tags.size())
            return {{}, {}, false};

        const auto target_tag = pool->tags[target_index];
        const bool target_allowed =
            reference_kind <= 4 ? target_tag == 9 :
            (reference_kind == 5 || reference_kind == 8) ? target_tag == 10 :
            (reference_kind == 6 || reference_kind == 7) ?
                (target_tag == 10 || target_tag == 11) :
                target_tag == 11;
        if (!target_allowed) return {{}, {}, false};

        const auto member = runtime.reviewed_member(*pool, target_index);
        if (!member.valid) return {{}, {}, false};

        // Recovered quirk: print the packed uint32, not a separately formatted
        // reference kind or target index.
        return {"MethodHandle",
                std::to_string(encoded) + ":" + member_text(runtime, member),
                true};
    }

    if (tag == 16) {
        const auto value = runtime.reviewed_utf8(
            *pool, static_cast<std::uint16_t>(encoded));
        return {"MethodType", runtime.original_quote_to_ascii(value.value), value.valid};
    }

    if (tag == 17 || tag == 18) {
        const auto value = runtime.reviewed_name_type(*pool, encoded >> 16);
        if (!value.valid) return {{}, {}, false};

        // Recovered quirk: print the whole packed word in the bootstrap-index
        // position rather than extracting and formatting only its low 16 bits.
        return {tag == 17 ? "Dynamic" : "InvokeDynamic",
                std::to_string(encoded) + ":" +
                    runtime.original_quote_to_ascii(value.name) + ":" +
                    runtime.original_quote_to_ascii(value.descriptor),
                true};
    }

    return {{}, {}, false};
}

// Recovered: Float and Double are rendered as raw uppercase bit patterns, not
// decimal floating-point values. UTF-8 uses the pool+48 resolver; String uses
// the distinct pool+56 symbol callback. Invalid UTF-8, String, class, or
// NameAndType lookups may retain a kind and partial quoted text with valid=false;
// invalid member/dynamic lookups return an empty representation. No Java name or
// descriptor syntax is validated. Twenty-nine original formatter branches were
// checked. This readable reconstruction was never compiled or executed.
}
