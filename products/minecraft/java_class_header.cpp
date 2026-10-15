#include "../../session/session_types.hpp"
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_class_header {
// Recovered: validate the minimum InstanceKlass metadata needed before the
// expensive class-body collectors run. Array classes and classes below the
// recovered loaded-state threshold are rejected here.
using Address = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Error {
    bool present = false;
    ByteString message;
};
template <class T> struct Read {
    T value;
    Error error;
};
struct Layout {
    std::optional<Address> name, pool, state, methods; // reader28/29/30/31
    std::uint8_t minimum_state = 0; // reader+40, initialized by separate VM-layout constructor
};
struct Header {
    ByteString raw_name;
    Address raw_pool = 0, methods = 0;
    std::uint8_t state = 0;
};
struct Contracts {
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Read<ByteString> symbol(Address reader, Address pointer) = 0; // 159
    virtual Read<Bytes> exact_read(Address, std::uint64_t) = 0;
    virtual void original_bounds_panic() = 0;
};
Read<Header> collect(Contracts &runtime, const Layout &layout, Address reader,
                     Address klass) { // yyk6Mm@1a9b340 header gates
    if (!layout.name || !layout.pool || !layout.state || !layout.methods)
        return {{}, {true, "InstanceKlass layout incomplete"}};
    const auto name_pointer = runtime.read_pointer(klass + *layout.name);
    if (name_pointer.error.present)
        return {{}, name_pointer.error};
    const auto name = runtime.symbol(reader, name_pointer.value);
    if (name.error.present)
        return {{}, name.error};
    if (!name.value.empty() && name.value.front() == '[')
        return {{}, {true, "array class"}}; // before state/pool/method reads
    const auto bytes = runtime.exact_read(klass + *layout.state, 1);
    if (bytes.error.present)
        return {{}, bytes.error};
    if (bytes.value.empty()) {
        runtime.original_bounds_panic();
        return {};
    }
    if (bytes.value[0] < layout.minimum_state)
        return {{}, {true, "class not loaded"}};
    const auto pool = runtime.read_pointer(klass + *layout.pool);
    if (pool.error.present)
        return {{}, pool.error};
    const auto methods = runtime.read_pointer(klass + *layout.methods);
    if (methods.error.present)
        return {{}, methods.error};
    return {{name.value, pool.value, methods.value, bytes.value[0]}, {}};
    // No explicit klass/name-pointer/raw-pool/method-pointer nonzero checks here.
    // The Symbol reader independently validates its input/cache. Later collectors
    // own nil-pool and nil-array handling. A successfully read empty name is accepted.
}
// Recovered: 31 paths cover missing layout slots, read/Symbol errors, nil values,
// and the exact loaded-state threshold comparison. This function maps only the
// class header gates; VMStruct discovery and body assembly are separate stages.
// Recovered ABI evidence identifies a 320-byte class result plus a Go error
// interface, replacing an earlier speculative boolean-return interpretation.
} // namespace ocean::reconstructed::minecraft_java_class_header
