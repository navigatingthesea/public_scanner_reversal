#include "../../session/session_types.hpp"
#include <functional>
#include <vector>

namespace ocean::reconstructed::minecraft_java_bytecode_references {
using Bytes = std::vector<std::uint8_t>;

struct Pool {
    Bytes tags;
    Bytes entries;
};
struct Step {
    std::int64_t length;
    bool valid;
};
struct Index {
    std::uint16_t value;
    bool valid;
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
struct Ref72 {
    std::uint16_t index;
    ByteString kind;
    ByteString owner;
    ByteString member;
    ByteString descriptor;
};
struct Member {
    Ref72 value;
    bool valid;
};
struct Representation {
    ByteString kind;
    ByteString text;
    bool valid;
};
struct Result {
    std::vector<Ref72> rows;
    std::vector<ByteString> text;
    bool valid;
};

struct Contracts {
    virtual bool reviewed_whole_bytecode_structural_validity(const Bytes&) = 0;
    virtual Step reviewed_instruction_length(const Bytes&, std::int64_t) = 0;
    virtual Index reviewed_operand_index(
        const Bytes&,
        std::int64_t,
        std::function<bool(std::uint16_t)>) = 0;
    virtual bool reviewed_literal_allowed(
        const Pool&,
        std::uint16_t,
        std::uint8_t mode) = 0;
    virtual Text reviewed_class_name(const Pool&, std::uint16_t) = 0;
    virtual Pair reviewed_name_type(const Pool&, std::uint16_t) = 0;
    virtual Member reviewed_member(const Pool&, std::uint16_t) = 0;
    virtual Representation reviewed_representation(const Pool&, std::uint16_t) = 0;
};

bool tag_is(
    const Pool& pool,
    std::uint16_t index,
    std::initializer_list<std::uint8_t> allowed_tags) {
    if (index == 0 || index >= pool.tags.size()) return false;
    for (const auto tag : allowed_tags)
        if (pool.tags[index] == tag) return true;
    return false;
}

std::uint32_t entry32(const Pool& pool, std::uint16_t index) {
    const auto offset = std::size_t{index} * 8;
    return std::uint32_t{pool.entries[offset]} |
        (std::uint32_t{pool.entries[offset + 1]} << 8) |
        (std::uint32_t{pool.entries[offset + 2]} << 16) |
        (std::uint32_t{pool.entries[offset + 3]} << 24);
}

Result collect(
    Contracts& runtime,
    const Pool* pool,
    const Bytes& bytecode) { // k6KL@1a50cc0
    if (pool == nullptr || pool->entries.size() != pool->tags.size() * 8 ||
        !runtime.reviewed_whole_bytecode_structural_validity(bytecode))
        return {{}, {}, false};

    Result result{{}, {}, true};
    const auto append_text = [&](std::int64_t pc,
                                 const ByteString& opcode,
                                 std::uint16_t index) {
        const auto representation = runtime.reviewed_representation(*pool, index);
        if (!representation.valid) return;
        result.text.push_back(
            "BC:" + std::to_string(pc) + ":" + opcode + ":" +
            std::to_string(index) + ":" + representation.kind + ":" +
            representation.text);
    };

    for (std::int64_t pc = 0; pc < static_cast<std::int64_t>(bytecode.size());) {
        const auto opcode = bytecode[pc];

        if (opcode == 0x12) { // ldc: one-byte constant-pool index
            const auto index = std::uint16_t{bytecode[pc + 1]};
            if (runtime.reviewed_literal_allowed(*pool, index, 0))
                append_text(pc, "ldc", index);
        } else if (opcode == 0x13 || opcode == 0x14) { // ldc_w / ldc2_w
            const auto mode = static_cast<std::uint8_t>(opcode == 0x14);
            const auto index = runtime.reviewed_operand_index(
                bytecode, pc, [&](auto value) {
                    return runtime.reviewed_literal_allowed(*pool, value, mode);
                });
            if (index.valid)
                append_text(pc, mode == 0 ? "ldc_w" : "ldc2_w", index.value);
        } else if (opcode >= 0xb2 && opcode <= 0xb9 &&
                   (opcode != 0xb9 ||
                    (bytecode[pc + 3] != 0 && bytecode[pc + 4] == 0))) {
            const auto index = runtime.reviewed_operand_index(
                bytecode, pc, [&](auto value) {
                    if (opcode <= 0xb5) return tag_is(*pool, value, {9});
                    if (opcode == 0xb6) return tag_is(*pool, value, {10});
                    if (opcode == 0xb9) return tag_is(*pool, value, {11});
                    return tag_is(*pool, value, {10, 11});
                });
            if (index.valid) {
                const auto member = runtime.reviewed_member(*pool, index.value);
                if (member.valid) result.rows.push_back(member.value);

                static const ByteString opcode_names[] = {
                    "getstatic", "putstatic", "getfield", "putfield",
                    "invokevirtual", "invokespecial", "invokestatic",
                    "invokeinterface",
                };
                append_text(pc, opcode_names[opcode - 0xb2], index.value);
            }
        } else if (opcode == 0xba &&
                   bytecode[pc + 3] == 0 && bytecode[pc + 4] == 0) {
            const auto index = runtime.reviewed_operand_index(
                bytecode, pc, [&](auto value) {
                    return tag_is(*pool, value, {18});
                });
            if (index.valid) {
                const auto encoded = entry32(*pool, index.value);
                const auto name_type =
                    runtime.reviewed_name_type(*pool, encoded >> 16);
                if (name_type.valid) {
                    result.rows.push_back({
                        index.value, "invokedynamic", {},
                        name_type.name, name_type.descriptor,
                    });
                }
                append_text(pc, "invokedynamic", index.value);
            }
        } else if (opcode == 0xbb || opcode == 0xbd ||
                   opcode == 0xc0 || opcode == 0xc1 ||
                   (opcode == 0xc5 && bytecode[pc + 3] != 0)) {
            const auto index = runtime.reviewed_operand_index(
                bytecode, pc, [&](auto value) {
                    return tag_is(*pool, value, {7, 100, 103});
                });
            if (index.valid) {
                const auto class_name =
                    runtime.reviewed_class_name(*pool, index.value);
                if (class_name.valid) {
                    result.rows.push_back(
                        {index.value, "type", class_name.value, {}, {}});
                }

                const ByteString operation =
                    opcode == 0xbb ? "new" :
                    opcode == 0xbd ? "anewarray" :
                    opcode == 0xc0 ? "checkcast" :
                    opcode == 0xc1 ? "instanceof" : "multianewarray";
                append_text(pc, operation, index.value);
            }
        }

        pc += runtime.reviewed_instruction_length(bytecode, pc).length;
    }
    return result;
}

// Recovered: a structural failure anywhere rejects the entire bytecode stream
// before collection. Individual invalid pool references are skipped without
// invalidating the result. Duplicate references and distinct instruction offsets
// are preserved. Field/method operations emit member rows; explicit class
// operations emit type rows; invokedynamic emits an ownerless name/descriptor
// row. MethodHandle constants appear only in textual evidence.
//
// invokeinterface requires a nonzero count and zero reserved byte;
// invokedynamic requires two zero reserved bytes; multianewarray requires a
// nonzero dimension. The values are not cross-checked against descriptors.
// Fifty-eight recovered parser paths were checked. This readable source was
// never compiled or executed.
}
