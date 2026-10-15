#include "../../session/session_types.hpp"
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_native_arrays {
// Recovered: bounded native Array<T> length reading and stable extraction of
// byte-array payloads used by annotation metadata parsers.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Error {
    bool present;
    ByteString message;
};
template <class T> struct Read {
    T value;
    Error error;
};
struct Layout {
    std::optional<Address> length, byte_array_body;
}; // reader80/96 optionaloffsetpointers
struct Blob {
    Bytes bytes;
    bool valid, unsupported;
};
struct Contracts {
    virtual Read<std::uint32_t> original_read32(Address) = 0;
    virtual Read<Bytes> original_exact_read_bytes(Address, std::uint64_t) = 0;
};
Read<std::uint32_t> count(Contracts &runtime, const Layout &layout, Address array) { // wMW@1a48ce0
    if (!layout.length)
        return {0, {true, "array length layout unavailable"}};
    const auto value = runtime.original_read32(array + *layout.length);
    if (value.error.present)
        return {0, value.error};
    if (value.value > 2000000)
        return {0, {true, "unreasonable array length"}};
    return value; // zero count accepted; this helper does not reject zero address
}
Blob annotation_bytes(Contracts &runtime, const Layout &layout, Address array) { // dxr@1a33000
    if (array == 0 || !layout.byte_array_body)
        return {{}, false, false};
    const auto length = count(runtime, layout, array);
    if (length.error.present)
        return {{}, false, false};
    // Recovered: an inner 4 MiB limit remains, but count()'s two-million-element
    // cap makes this branch unreachable through the fixed original caller.
    if (length.value > 0x400000)
        return {{}, false, true};
    const auto first =
        runtime.original_exact_read_bytes(array + *layout.byte_array_body, length.value);
    if (first.error.present)
        return {{}, false, false};
    const auto second =
        runtime.original_exact_read_bytes(array + *layout.byte_array_body, length.value);
    const auto after = count(runtime, layout, array); // attempted even if second read errored
    if (second.error.present || after.error.present || after.value != length.value ||
        first.value != second.value)
        return {{}, false, false};
    return {first.value, true, false}; // successful empty array accepted
}
// Recovered: count and blob paths preserve error ordering and the final length
// reread. The apparent 4 MiB unsupported branch is unreachable through this
// recovered caller because count() already enforces a two-million-byte cap.
// The resulting bytes feed annotation, parameter, type, and default-value parsers.
} // namespace ocean::reconstructed::minecraft_java_native_arrays
