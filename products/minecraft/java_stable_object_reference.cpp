#include "../../session/session_types.hpp"
#include <limits>
#include <vector>
namespace ocean::reconstructed::minecraft_java_stable_object_reference {
// Recovered: read a stable oop slot in ZGC, wide-oop, or compressed-oop mode and
// retain the raw encoding so the caller can verify the slot after object reads.
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
struct Context { // gdwyKn2,slotnamesverifiedbyconstructor192
    Address reader = 0;
    bool use_zgc = false, zgc_known = false, compressed_oops = false, oops_encoding_known = false;
    Address narrow_base = 0;
    std::uint32_t narrow_shift = 0; // 16/24
};
struct Reference {
    Address object = 0, raw = 0;
    bool valid = false, is_null = false;
};
struct Contracts {
    virtual Read<Address> read_pointer(Address reader, Address slot) = 0;
    virtual Read<std::uint32_t> read32(Address reader, Address slot) = 0;
    virtual Read<Bytes> exact_read(Address reader, Address slot, std::size_t count) = 0;
    virtual Valid<Address> decode_handle(Address reader, Address raw) = 0; // ieEhhZ4Tg@1a5e6a0
    virtual void original_bounds_panic() = 0;
};
Reference collect(Contracts &rt, const Context &ctx, Address slot) { // ejkacdBuGME@1a87a40
    if (!ctx.zgc_known)
        return {};
    if (ctx.use_zgc) {
        const auto a = rt.read_pointer(ctx.reader, slot);
        const auto b = rt.read_pointer(ctx.reader, slot);
        if (a.error || b.error || a.value != b.value)
            return {};
        if (!a.value)
            return {0, 0, true, true};
        const auto decoded = rt.decode_handle(ctx.reader, a.value);
        return {decoded.value, a.value, decoded.valid,
                false}; // invaliddecoderpartialobjectretained
    }
    if (!ctx.oops_encoding_known)
        return {};
    if (!ctx.compressed_oops) {
        const auto a = rt.read_pointer(ctx.reader, slot);
        const auto b = rt.read_pointer(ctx.reader, slot);
        return {a.value, a.value, !a.error && !b.error && a.value == b.value, a.value == 0};
        // Unlikehandlebranch,invalidwide results retain firstvalue/nullmarker.
    }
    const auto a = rt.exact_read(ctx.reader, slot, 4);
    const auto b = rt.exact_read(ctx.reader, slot, 4);
    if (a.error || b.error || a.value != b.value)
        return {};
    if (a.value.size() < 4) {
        rt.original_bounds_panic();
        return {};
    }
    const auto raw = std::uint32_t{a.value[0]} | (std::uint32_t{a.value[1]} << 8) |
                     (std::uint32_t{a.value[2]} << 16) | (std::uint32_t{a.value[3]} << 24);
    if (!raw)
        return {0, 0, true, true}; // beforebase/shiftvalidation
    if (ctx.narrow_shift > 16 ||
        Address{raw} >
            ((std::numeric_limits<Address>::max() - ctx.narrow_base) >> ctx.narrow_shift))
        return {0, raw, false, false};
    return {ctx.narrow_base + (Address{raw} << ctx.narrow_shift), raw, true, false};
}
bool still_matches(Contracts &rt, const Context &ctx, Address slot,
                   Address raw) { // iUuwwY0RIXSe@1a87cc0
    if (ctx.zgc_known && ctx.use_zgc) {
        const auto value = rt.read_pointer(ctx.reader, slot);
        return !value.error && value.value == raw;
    }
    if (!ctx.oops_encoding_known)
        return false;
    if (ctx.compressed_oops) {
        const auto value = rt.read32(ctx.reader, slot);
        return !value.error && Address{value.value} == raw;
    }
    const auto value = rt.read_pointer(ctx.reader, slot);
    return !value.error && value.value == raw;
    // Recovered: this recheck compares the raw slot encoding, not the decoded object.
}
// Recovered: all flag combinations establish ZGC priority, null handling,
// double-read failure/mismatch behavior, decoder failure, compressed-pointer
// overflow checks, and the accepted shift range (16 accepted, 17 rejected).
// Context creation and ZGC decoding are separate recovered stages.
} // namespace ocean::reconstructed::minecraft_java_stable_object_reference
