#include "../../session/session_types.hpp"
#include <optional>
namespace ocean::reconstructed::minecraft_java_zgc {
// Recovered: decode a ZGC pointer using HotSpot's exported load-bad mask and
// shift values, with rereads to reject metadata that changed during collection.
using Address = std::uint64_t;
struct Decoded {
    Address object = 0;
    bool valid = false;
};
struct Read {
    Address value = 0;
    bool error = false;
};
struct Contracts {
    virtual std::optional<Address> static_address(Address reader, const ByteString &type,
                                                  const ByteString &field) = 0;
    virtual std::optional<Address> field_offset(Address reader, const ByteString &type,
                                                const ByteString &field) = 0;
    virtual Read read_pointer(Address reader, Address) = 0;
};
Decoded decode(Contracts &rt, Address reader, Address raw) { // ieEhhZ4Tg@1a5e6a0
    const auto globals_address = rt.static_address(reader, "ZGlobalsForVMStructs", "_instance_p");
    const auto bad_mask_offset =
        rt.field_offset(reader, "ZGlobalsForVMStructs", "_ZPointerLoadBadMask");
    const auto shift_offset = rt.field_offset(reader, "ZGlobalsForVMStructs", "_ZPointerLoadShift");
    if (!globals_address || !bad_mask_offset || !shift_offset)
        return {};
    const auto globals = rt.read_pointer(reader, *globals_address);
    if (globals.error || globals.value == 0)
        return {};
    const auto mask_pointer = rt.read_pointer(reader, globals.value + *bad_mask_offset);
    if (mask_pointer.error)
        return {};
    const auto shift_pointer = rt.read_pointer(reader, globals.value + *shift_offset);
    if (shift_pointer.error)
        return {};
    const auto mask = rt.read_pointer(reader, mask_pointer.value);
    if (mask.error)
        return {};
    const auto shift = rt.read_pointer(reader, shift_pointer.value);
    if (shift.error)
        return {};
    if (mask.value == 0 || shift.value == 0 || shift.value >= 64 || (raw & mask.value) != 0)
        return {};
    const auto mask_again = rt.read_pointer(reader, mask_pointer.value);
    if (mask_again.error || mask_again.value != mask.value)
        return {};
    const Address decoded = raw >> shift.value;
    const auto shift_again = rt.read_pointer(reader, shift_pointer.value);
    return {decoded, !shift_again.error && shift_again.value == shift.value};
    // Mask instability discards decoded data. A final shift error/change retains
    // decoded data with valid=false. Zero raw/decoded pointers can be valid.
    // No guard rejects zero mask/shift POINTER addresses before the native read.
}
// Recovered: missing metadata, any of seven read failures, a bad pointer bit,
// zero/64-or-greater shifts, or changing mask/shift metadata invalidate the result.
// A stable shift of 63 is accepted.
} // namespace ocean::reconstructed::minecraft_java_zgc
