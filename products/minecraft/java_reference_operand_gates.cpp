#include "../../session/session_types.hpp"
#include <vector>
namespace ocean::reconstructed::minecraft_java_reference_operands {
using Bytes = std::vector<std::uint8_t>;

struct DynamicKind {
    std::uint8_t category;
    bool valid;
};
struct Pool {
    Bytes tags;
};
struct Contracts {
    virtual DynamicKind original_dynamic_constant_category(const Pool&,std::uint16_t)=0; //rEp; body in java_dynamic_literal_category.cpp
    virtual bool original_reference_index_validator(std::uint16_t)=0;
    virtual void original_bounds_panic()=0;
};
bool literal_allowed(
    Contracts& runtime,
    const Pool* pool,
    std::uint16_t index,
    std::uint8_t mode) { // qCf2wLs@1a50a60
    if (pool == nullptr || index == 0 || index >= pool->tags.size()) return false;

    const auto tag = pool->tags[index];
    if (tag == 17) {
        const auto dynamic = runtime.original_dynamic_constant_category(*pool, index);
        return dynamic.valid && dynamic.category == mode;
    }

    // Recovered: mode 0 is used by ldc/ldc_w; nonzero mode is used by ldc2_w.
    if (mode == 0)
        return tag == 3 || tag == 4 || tag == 7 || tag == 8 || tag == 15 ||
            tag == 16 || tag == 100 || tag == 103;
    return tag == 5 || tag == 6;
}
struct Index {
    std::uint16_t value;
    bool valid;
};

Index operand_index(Contracts& runtime, const Bytes& code, std::int64_t pc) { // fN1@1a50b80
    if (static_cast<std::int64_t>(code.size()) <= pc + 2) return {0, false};
    if (pc + 1 < 0) {
        runtime.original_bounds_panic();
        return {};
    }

    const auto first = code[pc + 1];
    const auto second = code[pc + 2];
    const auto big_endian = static_cast<std::uint16_t>((std::uint16_t{first} << 8) | second);
    const auto little_endian = static_cast<std::uint16_t>((std::uint16_t{second} << 8) | first);

    if (!runtime.original_reference_index_validator(big_endian)) return {0, false};

    // Recovered: reject the operand if both byte orders are distinct and valid.
    // Interpretation: this conservative ambiguity check prevents accepting a
    // reference when byte order cannot be established from pool validity alone.
    if (big_endian != little_endian &&
        runtime.original_reference_index_validator(little_endian))
        return {0, false};
    return {big_endian, true};
}
// Recovered: the literal gate was checked across all 256 tags in both modes,
// plus nil/range/dynamic cases. The operand reader was checked for truncation,
// byte-order ambiguity, equal bytes, and pc=-1. The parent walker normally
// supplies a valid instruction offset. These helpers emit no rule verdict.
// This readable reconstruction was never compiled or executed.
}
