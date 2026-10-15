#include "../../session/session_types.hpp"
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_pool_snapshot {
// Recovered: snapshot constant-pool tags and entries twice, accept only stable
// buffers, and expose callbacks that resolve Symbol-backed UTF-8 entries.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Error {
    bool present;
};
template <class T> struct Read {
    T value;
    Error error;
};
struct Text {
    ByteString value;
    bool valid;
};
struct Layout {
    std::optional<Address> tags, length, entries, tag_array_body;
}; // reader15/16/17/12
struct Snapshot {
    Bytes tags, entries;
    Address reader, pool;
}; // original64byte parsed-pool plus captured callbacks
struct Contracts {
    virtual Read<std::uint32_t> read32(Address) = 0;
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Read<Bytes> exact_read(Address, std::uint64_t) = 0;
    virtual Read<ByteString> symbol(Address reader,
                                    Address address) = 0; // source159 cache/raw bytes/errors
    virtual void
    cache_pool_string_under_shared_mutex(Address reader, Address pool, std::uint16_t index,
                                         const ByteString &) = 0; // reader+16 mutex,reader+32 map
    virtual void original_bounds_panic() = 0;
};
std::optional<Snapshot> capture(Contracts &runtime, const Layout &layout, Address reader,
                                Address pool) { // smmXDyH@1a4d200
    if (!pool || !layout.tags || !layout.length || !layout.entries || !layout.tag_array_body)
        return {};
    const auto length = runtime.read32(pool + *layout.length);
    if (length.error.present || length.value == 0 || length.value > 65536)
        return {};
    const auto tag_pointer = runtime.read_pointer(pool + *layout.tags);
    if (tag_pointer.error.present || !tag_pointer.value)
        return {};
    const auto tags = runtime.exact_read(tag_pointer.value + *layout.tag_array_body, length.value);
    if (tags.error.present)
        return {};
    const auto entries =
        runtime.exact_read(pool + *layout.entries, std::uint64_t(length.value) * 8);
    if (entries.error.present)
        return {};
    const auto second_tags =
        runtime.exact_read(tag_pointer.value + *layout.tag_array_body, length.value);
    const auto second_entries =
        runtime.exact_read(pool + *layout.entries, std::uint64_t(length.value) *
                                                       8); // attempted even if second_tags errored
    if (second_tags.error.present || second_entries.error.present ||
        tags.value != second_tags.value || entries.value != second_entries.value)
        return {};
    return Snapshot{tags.value, entries.value, reader,
                    pool}; // retains FIRST buffers; no length/pointer reread
}
Text utf8(Contracts &runtime, const Snapshot &snapshot,
          std::uint16_t index) { // smmXDyH.func1@1a4d6a0
    if (index == 0 || index >= snapshot.tags.size() || snapshot.tags[index] != 1)
        return {{}, false};
    const auto offset = std::size_t(index) * 8;
    if (offset > snapshot.entries.size() || snapshot.entries.size() - offset < 8) {
        runtime.original_bounds_panic();
        return {};
    }
    Address symbol_pointer = 0;
    for (unsigned k = 0; k < 8; ++k)
        symbol_pointer |= Address(snapshot.entries[offset + k]) << (k * 8); // little endian
    const auto result = runtime.symbol(snapshot.reader, symbol_pointer);
    if (!result.error.present)
        runtime.cache_pool_string_under_shared_mutex(snapshot.reader, snapshot.pool, index,
                                                     result.value);
    return {result.value,
            !result.error.present}; // partial string retained even on error; empty success cached
}
Text native_string(Contracts &runtime, const Snapshot &snapshot,
                   Address symbol_pointer) { // smmXDyH.func2@1a4d660
    const auto result = runtime.symbol(snapshot.reader, symbol_pointer);
    return {result.value, !result.error.present}; // no additional pool-string-cache write
}
// Recovered: utf8() does not consult the pool-string cache first. It resolves the
// captured entry through the Symbol reader, whose own cache runs first, then writes
// successful text to the shared pool cache. Invalid UTF-8/MUTF-8 and NUL bytes are
// preserved. The snapshot caps pools at 65,536 entries (524,288 entry bytes).
} // namespace ocean::reconstructed::minecraft_java_pool_snapshot
