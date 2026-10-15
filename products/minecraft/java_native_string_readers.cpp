#include "../../session/session_types.hpp"
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>
namespace ocean::reconstructed::minecraft_java_native_strings {
// Recovered: read HotSpot Symbol bytes and CONSTANT_Utf8 entries with shared
// caches. Bytes are preserved verbatim; this layer does not validate UTF-8 or
// modified UTF-8 encoding.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Error {
    bool present = false;
    ByteString message;
};
template <class T> struct Result {
    T value;
    Error error;
};
struct Layout {
    std::optional<Address> symbol_length, symbol_body; // collector slots13/14
    std::optional<Address> pool_tags, pool_length, pool_body, tag_array_body; // 15/16/17/12
};
struct Contracts {
    virtual Result<std::uint16_t> original_read16(Address) = 0;
    virtual Result<std::uint32_t> original_read32(Address) = 0;
    virtual Result<Address> original_read_pointer(Address) = 0;
    virtual Result<Bytes> original_exact_read_bytes(Address, std::uint64_t) = 0;
    virtual void original_bounds_panic() = 0;
};
struct Reader {
    Layout layout;
    std::mutex cache_mutex;                // original reader mutex at+16 protects BOTH caches
    std::map<Address, ByteString> symbols; // original+24
    std::map<std::pair<Address, std::uint16_t>, ByteString> pool_strings; // original+32
};
Result<ByteString> symbol(Reader &reader, Contracts &runtime, Address address) { // hZi@1a47480
    {
        const std::lock_guard lock(reader.cache_mutex);
        const auto cached = reader.symbols.find(address);
        if (cached != reader.symbols.end())
            return {cached->second, {}};
    }
    if (address == 0 || !reader.layout.symbol_length || !reader.layout.symbol_body)
        return {{}, {true, "Symbol layout unavailable"}};
    const auto length = runtime.original_read16(address + *reader.layout.symbol_length);
    if (length.error.present || length.value > 16384)
        return {{}, {true, "invalid Symbol length"}};
    const auto bytes =
        runtime.original_exact_read_bytes(address + *reader.layout.symbol_body, length.value);
    if (bytes.error.present)
        return {{}, bytes.error};
    ByteString text(bytes.value.begin(), bytes.value.end()); // raw bytes, no UTF8/MUTF8 validation
    {
        const std::lock_guard lock(reader.cache_mutex);
        reader.symbols[address] = text;
    }
    return {text, {}}; // zero length is successful and cached
}
Result<ByteString> pool_utf8(Reader &reader, Contracts &runtime, Address pool,
                             std::uint16_t index) {
    // Recovered jjCB@1a478c0: the key is pool address plus uint16 index. Padding
    // in the original 16-byte key is not semantic.
    const auto key = std::make_pair(pool, index);
    {
        const std::lock_guard lock(reader.cache_mutex);
        const auto cached = reader.pool_strings.find(key);
        if (cached != reader.pool_strings.end())
            return {cached->second, {}};
    }
    if (!reader.layout.pool_tags || !reader.layout.pool_length || !reader.layout.pool_body ||
        !reader.layout.tag_array_body)
        return {{}, {true, "constant-pool layout unavailable"}};
    const auto count = runtime.original_read32(pool + *reader.layout.pool_length);
    if (count.error.present || count.value > 65536 || index == 0 || index >= count.value)
        return {{}, {true, "constant-pool index out of range"}};
    const auto tags = runtime.original_read_pointer(pool + *reader.layout.pool_tags);
    if (tags.error.present)
        return {{}, tags.error};
    const auto tag =
        runtime.original_exact_read_bytes(tags.value + *reader.layout.tag_array_body + index, 1);
    if (tag.error.present)
        return {{}, {true, "constant-pool entry is not Utf8"}};
    if (tag.value.empty()) {
        runtime.original_bounds_panic();
        return {};
    }
    if (tag.value[0] != 1)
        return {{}, {true, "constant-pool entry is not Utf8"}};
    const auto pointer =
        runtime.original_read_pointer(pool + *reader.layout.pool_body + std::uint64_t{index} * 8);
    if (pointer.error.present)
        return {{}, pointer.error};
    const auto text = symbol(reader, runtime, pointer.value);
    if (!text.error.present) {
        const std::lock_guard lock(reader.cache_mutex);
        reader.pool_strings[key] = text.value;
    }
    return text;
}
// Recovered: cache lookup precedes validation, so a previously cached zero address
// or index zero is returned. Empty successful strings are cached; failures are
// retried. There is no expiry. Locks are released before remote reads, allowing
// concurrent callers to duplicate work and overwrite the same cache entry.
} // namespace ocean::reconstructed::minecraft_java_native_strings
