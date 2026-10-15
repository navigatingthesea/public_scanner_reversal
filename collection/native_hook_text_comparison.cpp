#include "../session/session_types.hpp"
#include <algorithm>
namespace ocean::reconstructed::native_hook_text {
// Recovered: compare local and remote .text bytes, decode changed instruction
// boundaries, and report only INT3, NOP, or JMP replacements. INT3/NOP rows do
// not increment the returned JMP count; unreadable/undecodable candidates are skipped.
using Address = std::uint64_t;
enum class Mnemonic : std::uint32_t { Int3 = 0x11f, Jmp = 0x133, Nop = 0x1e3 };
struct Operand {
    std::uint32_t type = 0;
    std::uint8_t immediate_relative = 0;
    Address immediate_value = 0;
};
struct Decoded {
    std::int32_t status = 0;
    std::uint32_t mnemonic = 0;
    std::uint8_t length = 0, operand_count = 0;
    std::vector<Operand> operands;
};
struct Module {
    ByteString name;
    Address remote_base = 0, disk_buffer = 0, remote_copy = 0;
    std::uint32_t text_rva = 0, text_raw_offset = 0, text_virtual_size = 0;
};
struct Contracts {
    virtual bool memory_equal(Address first, Address second, std::size_t count) = 0;
    virtual std::uint8_t unsafe_byte(Address) = 0;
    virtual std::uint16_t unsafe_u16(Address) = 0;
    virtual Address unsafe_u64(Address) = 0;
    virtual Decoded decode(Address bytes,
                           std::size_t available) = 0; // 3411700, max5 operands, mode1
    virtual void calculate_absolute_operand(const Decoded &, const Operand &, Address runtime,
                                            Address &initialized_zero_output) = 0;
    virtual ByteString symbol_for_module_rva(Address remote_copy, std::uint32_t rva) = 0; // 33ca6c0
    virtual ByteString format_instruction(const Decoded &, Address runtime,
                                          std::size_t capacity) = 0;
    virtual ByteString describe_destination(Address) = 0; // 33cac00
    virtual std::uint32_t read_remote_14(Address target, Address &local_buffer) = 0;
    virtual ByteString format_hook(const ByteString &format, Address where,
                                   const ByteString &module, const ByteString &symbol,
                                   const ByteString &text) = 0;
};
Address branch_destination(Contracts &rt, const Decoded &instruction, Address bytes,
                           Address runtime) {
    if (rt.unsafe_u16(bytes) == 0x25ff)
        return rt.unsafe_u64(bytes + instruction.length);
    // FF25 special case reads inline QWORD immediately AFTER decoded instruction;
    // RIP displacement is not used here. No remaining-byte bound added.
    for (std::size_t k = 0; k < instruction.operand_count; ++k) {
        const auto &operand = instruction.operands[k];
        if (operand.type == 4) { // immediate operand
            if (operand.immediate_relative == 0)
                return operand.immediate_value;
            if (operand.immediate_relative != 1)
                continue;
        } else if (operand.type != 2)
            continue; // memory allowed; REGISTER operands ignored
        Address result = 0;
        rt.calculate_absolute_operand(instruction, operand, runtime, result);
        return result; // calculation status ignored
    }
    return 0;
}
std::uint32_t compare_text(Contracts &rt, const Module &module,
                           std::vector<ByteString> &hooks) { // 33cb510..33cbe42
    const auto size = std::uint64_t(module.text_virtual_size);
    std::uint64_t offset = 0;
    std::uint32_t jumps_reported = 0;
    while (offset < size) {
        const auto count = std::min<std::uint64_t>(64, size - offset);
        const auto end = offset + count;
        const auto disk = module.disk_buffer + module.text_raw_offset;
        const auto memory = module.remote_copy + module.text_rva;
        if (rt.memory_equal(disk + offset, memory + offset, count)) {
            offset = end;
            continue;
        }
        while (offset < end) {
            const auto byte = rt.unsafe_byte(memory + offset);
            const bool candidate =
                byte == 0xcc || byte == 0x90 || byte == 0xe9 || byte == 0xeb || byte == 0xff;
            if (rt.unsafe_byte(disk + offset) == byte || !candidate) {
                ++offset;
                continue;
            }
            const auto instruction = rt.decode(memory + offset, size - offset);
            if (instruction.status < 0) {
                ++offset;
                continue;
            }
            const auto original_length = instruction.length;
            const auto mnemonic = instruction.mnemonic;
            if (mnemonic != std::uint32_t(Mnemonic::Int3) &&
                mnemonic != std::uint32_t(Mnemonic::Nop) &&
                mnemonic != std::uint32_t(Mnemonic::Jmp)) {
                offset += original_length;
                continue;
            }
            const auto runtime = module.remote_base + module.text_rva + offset;
            const auto symbol = rt.symbol_for_module_rva(
                module.remote_copy, std::uint32_t(runtime) - std::uint32_t(module.remote_base));
            if (mnemonic == std::uint32_t(Mnemonic::Int3) ||
                mnemonic == std::uint32_t(Mnemonic::Nop)) {
                const auto formatted = rt.format_instruction(instruction, runtime, 256);
                hooks.push_back(rt.format_hook("[0] [%p] [%s!%s] [%s]", runtime, module.name,
                                               symbol, formatted));
                // INT3/NOP append a row but do NOT increment the numeric return count.
            } else {
                const auto target = branch_destination(rt, instruction, memory + offset, runtime);
                const auto first_label = rt.describe_destination(target);
                Address next_bytes = 0;
                if (rt.read_remote_14(target, next_bytes) == 0) {
                    offset +=
                        original_length; // additional advance below: failed read skips TWO lengths
                } else {
                    const auto second = rt.decode(next_bytes, 14);
                    if (second.status < 0 || second.mnemonic != std::uint32_t(Mnemonic::Jmp)) {
                        hooks.push_back(rt.format_hook("[1] [%p] [%s!%s] [jmp %s]", runtime,
                                                       module.name, symbol, first_label));
                    } else {
                        const auto final_target =
                            branch_destination(rt, second, next_bytes, target);
                        const auto second_label = rt.describe_destination(final_target);
                        hooks.push_back(rt.format_hook("[2] [%p] [%s!%s] [jmp %s]", runtime,
                                                       module.name, symbol, second_label));
                    }
                    ++jumps_reported; // uint32 wrap preserved, one per original JMP
                }
            }
            offset += original_length;
        }
    }
    return jumps_reported;
}
// Snapshots use global decoded-instruction/operand scratch77923e0/7792550;
// logical locals above preserve the first length before second decode overwrites
// that scratch. No synchronization/stability re-read is added.
// Candidate bytes are NOT independently a match: decoded mnemonic must be one
// of INT3/NOP/JMP. CALL byteE8 isn't inspected. No arbitrary byte-diff alert,
// relocation normalization or minimum hook count is performed in this body.
// Opcode-to-enum identities proven with eight ORIGINAL decoder runs, no enum
// guessing.25 comparator routes incl eight using that original decoder.
// Native reads/symbols/formatting were synthetic contracts; formatted hook text
// models validate control/arguments, not all CRT formatting edge cases.
// Protected ReadProcessMemory-like thunk799b4bb rewrites return to+6; dynamically
// decoded continuation tests EAX!=0. The linear draft's huge write and status
// mask0x47 are overlapping-code artifacts and are deliberately excluded here.
// Other protected thunks/API export names, module enumeration and file/symbol/
// destination helpers remain separately reviewed dependencies. No compile/run.
} // namespace ocean::reconstructed::native_hook_text
