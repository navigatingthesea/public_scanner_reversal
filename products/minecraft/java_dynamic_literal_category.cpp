#include "../../session/session_types.hpp"
#include <vector>
namespace ocean::reconstructed::minecraft_java_dynamic_literals {
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
struct Category {
    // 0: an ordinary one-slot LDC value. 1: a two-slot long/double value.
    std::uint8_t value;
    bool valid;
};
struct Contracts {
    virtual Text original_utf8_callback_at_pool48(std::uint16_t)=0;
    virtual Pair reviewed_name_and_type(const Pool&,std::uint16_t)=0; //source162
    virtual void original_bounds_panic()=0;
};
Text utf8(Contracts& runtime, const Pool* pool, std::uint16_t index) { // fmPh@1a4d9c0
    if (pool == nullptr || index == 0 || index >= pool->tags.size() || pool->tags[index] != 1)
        return {{}, false};

    // Recovered: the callback stored at pool+48 owns UTF-8 resolution. This
    // wrapper performs only the constant-pool bounds and tag checks.
    return runtime.original_utf8_callback_at_pool48(index);
}

Category dynamic(Contracts& runtime, const Pool* pool, std::uint16_t index) { // rEp@1a50960
    if (pool == nullptr || index == 0 || index >= pool->tags.size() || pool->tags[index] != 17)
        return {0, false};

    const auto entry_offset = std::size_t{index} * 8;
    if (entry_offset > pool->entries.size() || pool->entries.size() - entry_offset < 4) {
        runtime.original_bounds_panic();
        return {};
    }

    const auto encoded = std::uint32_t{pool->entries[entry_offset]} |
        (std::uint32_t{pool->entries[entry_offset + 1]} << 8) |
        (std::uint32_t{pool->entries[entry_offset + 2]} << 16) |
        (std::uint32_t{pool->entries[entry_offset + 3]} << 24);
    const auto name_and_type = runtime.reviewed_name_and_type(*pool, encoded >> 16);
    if (!name_and_type.valid || name_and_type.descriptor.empty()) return {0, false};

    // Recovered: only the first descriptor byte is inspected. The helper does
    // not validate the rest of the descriptor, so "Jgarbage" is still wide.
    const char first = name_and_type.descriptor.front();
    return {static_cast<std::uint8_t>(first == 'J' || first == 'D'), true};
}
// Recovered: tag 17 is CONSTANT_Dynamic. Category 1 is accepted by ldc2_w;
// category 0 is accepted by ldc/ldc_w. [J, ()J, and arbitrary descriptors are
// classified as ordinary because their first byte is neither J nor D.
//
// Interpretation: this is a bytecode operand-width gate, not a detection rule.
// It emits no score or evidence by itself. Sixteen original paths were checked.
// This readable reconstruction was never compiled or executed.
}
