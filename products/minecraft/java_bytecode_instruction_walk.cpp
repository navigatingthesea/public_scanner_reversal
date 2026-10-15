#include "../../session/session_types.hpp"
#include <bit>
#include <vector>

namespace ocean::reconstructed::minecraft_java_bytecode {
using Bytes = std::vector<std::uint8_t>;

struct Step {
    std::int64_t length;
    bool valid;
};

// Recovered JVM instruction sizes for opcodes 0x00..0xC9. A zero marks one
// of the variable-length instructions handled explicitly below.
const std::uint8_t ordinary_lengths[202] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,3,2,3,3,2,2,2,2,2,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,3,3,3,3,3,3,
    3,3,3,3,3,3,3,3,3,2,0,0,1,1,1,1,1,1,3,3,3,3,3,3,3,5,5,3,2,3,1,1,
    3,3,1,1,0,4,3,3,5,5,
};

std::int32_t signed_big_endian32(const Bytes& code, std::size_t at) {
    const std::uint32_t value = (std::uint32_t(code[at]) << 24) |
        (std::uint32_t(code[at + 1]) << 16) |
        (std::uint32_t(code[at + 2]) << 8) |
        code[at + 3];
    return std::bit_cast<std::int32_t>(value);
}

Step instruction(const Bytes& code, std::int64_t pc) { // ynOX@1a55380
    const auto size = static_cast<std::int64_t>(code.size());
    if (pc < 0 || pc >= size) return {0, false};

    const auto opcode = code[static_cast<std::size_t>(pc)];
    if (opcode > 0xc9) return {0, false};

    std::int64_t length;
    if (opcode == 0xaa || opcode == 0xab) {
        // tableswitch/lookupswitch operands start at the next four-byte boundary.
        const auto aligned = (pc + 4) & ~std::int64_t{3};
        if (size < aligned + 8) return {0, false};

        if (opcode == 0xaa) {
            if (size < aligned + 12) return {0, false};
            const auto low = signed_big_endian32(code, aligned + 4);
            const auto high = signed_big_endian32(code, aligned + 8);
            const auto range = std::int64_t{high} - low;
            if (range < 0 || range > 65535) return {0, false};
            length = aligned - pc + 16 + range * 4;
        } else {
            const auto pair_count = signed_big_endian32(code, aligned + 4);
            if (pair_count < 0 || pair_count > 65536) return {0, false};
            length = aligned - pc + 8 + std::int64_t{pair_count} * 8;
        }
    } else if (opcode == 0xc4) {
        if (pc + 1 >= size) return {0, false};
        const auto modified_opcode = code[pc + 1];
        if (modified_opcode == 0x84)
            length = 6; // wide iinc
        else if ((modified_opcode >= 0x15 && modified_opcode <= 0x19) ||
                 (modified_opcode >= 0x36 && modified_opcode <= 0x3a) ||
                 modified_opcode == 0xa9)
            length = 4;
        else
            return {0, false};
    } else {
        length = ordinary_lengths[opcode];
    }

    // Recovered: preserve the computed length even when the operand is truncated.
    return {length, length <= size - pc};
}

struct Opcodes {
    Bytes values;
    bool complete;
};

Opcodes extract(const Bytes& code) { // y_Z@1a55640
    Opcodes result{{}, true};
    for (std::int64_t pc = 0; pc < static_cast<std::int64_t>(code.size());) {
        const auto step = instruction(code, pc);
        if (!step.valid) {
            result.complete = false;
            return result;
        }
        result.values.push_back(code[pc]);
        pc += step.length;
    }
    return result;
}

// Recovered: opcodes 0x00..0xC9 are accepted, including unused one-byte slots;
// 0xCA..0xFF are rejected. The walk does not validate branches, switch-key
// ordering, local-variable indices, or switch padding bytes. `complete` means
// only that this scanner could traverse the byte stream; it is not JVM verifier
// approval. On failure, earlier opcodes remain in the result.
//
// All 256 opcode bytes and 29 wide/switch/alignment/truncation cases were
// checked against the recovered leaf. This source was never compiled or run.
}
