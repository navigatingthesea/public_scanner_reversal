#include "../../session/session_types.hpp"
#include <unordered_set>
#include <vector>
namespace ocean::reconstructed::minecraft_java_dictionary_walk {
// Recovered: registry mode 2 enumerates InstanceKlass pointers from the legacy
// SystemDictionary hash table. It deduplicates entry nodes and class pointers
// globally while retaining successfully decoded rows after per-bucket faults.
using Address = std::uint64_t;
struct Error {
    bool present = false;
    ByteString message;
};
template <class T> struct Read {
    T value;
    Error error;
};
struct Entry {
    Address klass = 0, raw_context = 0;
    std::uint8_t context_flag = 0;
};
struct Contracts {
    virtual Address
    layout_value(Address reader,
                 const ByteString &key) = 0; // reader8->VMmeta56 stringmap, missing=>zero
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Read<std::uint32_t> read32(Address) = 0;
    virtual Error wrap_error(const ByteString &format, const Error &) = 0; // fmt.Errorf %w
};
Read<std::vector<Entry>> collect(Contracts &rt, Address reader) { // vTeJ9wLfhjr@1aa5240,mode2
    const auto dictionary = rt.read_pointer(rt.layout_value(reader, "dictionary_addr"));
    if (dictionary.error.present)
        return {{}, rt.wrap_error("read SystemDictionary: %w", dictionary.error)};
    const auto size = rt.read32(dictionary.value + rt.layout_value(reader, "table_size_off"));
    if (size.error.present)
        return {{}, rt.wrap_error("read SystemDictionary size: %w", size.error)};
    const auto buckets = rt.read_pointer(dictionary.value + rt.layout_value(reader, "buckets_off"));
    if (buckets.error.present)
        return {{}, rt.wrap_error("read SystemDictionary buckets: %w", buckets.error)};
    // No dictionary-pointer nil guard before these reads; tablevalidation occurs
    // only after reading BOTH size and bucketspointer.
    if (size.value == 0 || size.value > 250000 || buckets.value == 0)
        return {{}, {true, "invalid SystemDictionary table"}};
    std::vector<Entry> out;
    std::unordered_set<Address> seen_entries, seen_classes;
    for (std::uint32_t bucket = 0; bucket < size.value; ++bucket) {
        const auto stride = rt.layout_value(reader, "bucket_size");
        const auto first = rt.read_pointer(buckets.value + Address{bucket} * stride +
                                           rt.layout_value(reader, "bucket_entry_off"));
        if (first.error.present)
            continue;
        Address entry = first.value;
        for (std::uint32_t steps = 0; entry != 0 && steps < 2000000; ++steps) {
            if (!seen_entries.insert(entry).second)
                break; // global acrossALLbuckets
            const auto literal =
                rt.read_pointer(entry + rt.layout_value(reader, "entry_literal_off"));
            if (!literal.error.present && literal.value &&
                seen_classes.insert(literal.value).second)
                out.push_back({literal.value, 0, 0}); // No low-bit mask; no loader context.
            const auto next = rt.read_pointer(entry + rt.layout_value(reader, "entry_next_off"));
            if (next.error.present)
                break;
            entry = next.value;
        } // Two-million-link cap per bucket; prior rows remain usable.
    }
    return {std::move(out), {}};
}
// Recovered: 14 control-flow routes cover duplicate nodes/classes, missing or
// unreadable literals, bucket/link failures, cycles, and fatal table-header
// failures. A size of 250001 is rejected only after the bucket pointer read.
// Interpretation: the 250000 buckets and two-million links are corruption/
// runaway guards; very large walks were not exhaustively emulated.
} // namespace ocean::reconstructed::minecraft_java_dictionary_walk
