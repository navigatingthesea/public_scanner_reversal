#include "../../session/session_types.hpp"
#include <vector>

namespace ocean::reconstructed::minecraft_java_pool_records {
using Bytes = std::vector<std::uint8_t>;

struct Pool {
    Bytes tags;
    Bytes entries; // Eight bytes per native parsed-pool entry.
};
struct Text {
    ByteString value;
    bool valid;
};
struct NameType {
    ByteString name;
    ByteString descriptor;
    bool valid;
};
struct Member72 {
    std::uint16_t index;
    ByteString kind;
    ByteString owner;
    ByteString member;
    ByteString descriptor;
};
struct Member {
    Member72 value;
    bool valid;
};

struct Contracts {
    virtual Text original_parsed_pool_utf8(
        const Pool&,
        std::uint16_t) = 0; // fmPh/source163
    virtual void original_bounds_panic() = 0;
};

bool index_exists(const Pool* pool, std::uint16_t index) {
    return pool != nullptr && index != 0 && index < pool->tags.size();
}

std::uint32_t entry_word(
    Contracts& runtime,
    const Pool& pool,
    std::uint16_t index) {
    const auto offset = std::size_t{index} * 8;
    if (offset > pool.entries.size() || pool.entries.size() - offset < 4) {
        runtime.original_bounds_panic();
        return 0;
    }
    return std::uint32_t{pool.entries[offset]} |
        (std::uint32_t{pool.entries[offset + 1]} << 8) |
        (std::uint32_t{pool.entries[offset + 2]} << 16) |
        (std::uint32_t{pool.entries[offset + 3]} << 24);
}

Text class_name(
    Contracts& runtime,
    const Pool* pool,
    std::uint16_t index) { // aEk@1a4da40
    if (!index_exists(pool, index)) return {{}, false};
    const auto tag = pool->tags[index];
    if (tag != 7 && tag != 100 && tag != 103) return {{}, false};

    // Recovered parsed-pool layout: the UTF-8 name index is in the high 16 bits.
    const auto encoded = entry_word(runtime, *pool, index);
    return runtime.original_parsed_pool_utf8(*pool, encoded >> 16);
}

NameType name_and_type(
    Contracts& runtime,
    const Pool* pool,
    std::uint16_t index) { // iCPP@1a4db20
    if (!index_exists(pool, index) || pool->tags[index] != 12)
        return {{}, {}, false};

    const auto encoded = entry_word(runtime, *pool, index);
    const auto name = runtime.original_parsed_pool_utf8(
        *pool, static_cast<std::uint16_t>(encoded));
    const auto descriptor = runtime.original_parsed_pool_utf8(
        *pool, encoded >> 16); // Attempted even when name lookup failed.
    return {name.value, descriptor.value, name.valid && descriptor.valid};
}

Member member(
    Contracts& runtime,
    const Pool* pool,
    std::uint16_t index) { // fkzg@1a4dc20
    if (!index_exists(pool, index)) return {{}, false};
    const auto tag = pool->tags[index];
    if (tag != 9 && tag != 10 && tag != 11) return {{}, false};

    const auto encoded = entry_word(runtime, *pool, index);
    const auto owner = class_name(
        runtime, pool, static_cast<std::uint16_t>(encoded));
    const auto name_type = name_and_type(runtime, pool, encoded >> 16);
    if (!owner.valid || !name_type.valid) return {{}, false};

    return {{index,
             tag == 9 ? "field" : "method",
             owner.value,
             name_type.name,
             name_type.descriptor},
            true};
}

// Recovered: native entry words are little-endian. Member entries store the
// class index in low 16 bits and NameAndType index in high 16 bits. NameAndType
// stores name low and descriptor high. Tags 10 and 11 both produce kind
// `method`; tag 9 produces `field`. Empty names may be valid, and no syntax
// validation is applied to class names or descriptors.
//
// The parent reference scanner first requires entries.size()==tags.size()*8.
// Thirteen original resolution paths were checked. UTF-8 cache initialization
// and native pool production remain separate. This source was never compiled or
// executed.
}
