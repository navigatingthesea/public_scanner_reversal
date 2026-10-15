#include "../../session/session_types.hpp"
#include <vector>

namespace ocean::reconstructed::minecraft_java_pool_lists {
using Address = std::uint64_t;

struct Text {
    ByteString value;
    bool valid;
};
struct Reference {
    std::uint16_t index;
    ByteString kind;
    ByteString owner;
    ByteString member;
    ByteString descriptor;
};
struct Member {
    Reference reference;
    bool valid;
};
struct Constant {
    ByteString kind;
    ByteString text;
    bool valid;
};
struct PoolView {
    Address pool;
    std::uint64_t tag_count;
    std::uint64_t entries_byte_count;
};

struct Contracts {
    virtual Text utf8(Address pool, std::uint16_t index) = 0;
    virtual Member member(Address pool, std::uint16_t index) = 0;
    virtual Constant constant(Address pool, std::uint16_t index) = 0;
};

std::vector<ByteString> strings(
    Contracts& runtime,
    const PoolView& pool) { // rwM@1a4d860
    std::vector<ByteString> result;
    if (pool.pool == 0) return result;

    for (std::uint64_t index = 1; index < pool.tag_count; ++index) {
        const auto value = runtime.utf8(pool.pool, std::uint16_t(index));
        if (value.valid && !value.value.empty()) result.push_back(value.value);
    }
    return result;
}

std::vector<Reference> references(
    Contracts& runtime,
    const PoolView& pool) { // g3@1a4dee0
    std::vector<Reference> result;
    if (pool.pool == 0) return result;

    for (std::uint64_t index = 1; index < pool.tag_count; ++index) {
        const auto value = runtime.member(pool.pool, std::uint16_t(index));
        if (value.valid) result.push_back(value.reference);
    }
    return result;
}

std::vector<ByteString> constants(
    Contracts& runtime,
    const PoolView& pool) { // diq@1a50580
    std::vector<ByteString> result;
    if (pool.pool == 0 || pool.tag_count > 65536 ||
        pool.entries_byte_count != pool.tag_count * 8)
        return result;

    for (std::uint64_t index = 1; index < pool.tag_count; ++index) {
        const auto value = runtime.constant(pool.pool, std::uint16_t(index));
        if (!value.valid) continue;
        result.push_back(
            "CP:" + std::to_string(index) + ":" + value.kind + ":" + value.text);
    }
    return result;
}

// Recovered: all three walks preserve pool order and duplicates. String evidence
// omits valid empty UTF-8 entries. Member rows may contain valid empty strings.
// Constant evidence includes valid empty UTF-8 representations and prefixes each
// value with `CP:<index>:`. The string and member loops have no local 65,536 or
// entry-shape guard and cast every index to uint16; the native pool constructor
// normally imposes that bound. The constant loop verifies both conditions.
//
// Interpretation: these are raw evidence lists. Later SDK rules decide whether
// any item contributes to a report. Twenty original routes were checked. This
// readable reconstruction was never compiled or executed.
}
