#include "../../session/session_types.hpp"
#include <algorithm>
#include <functional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_class_registry {
// Recovered: select one of the two registry walkers, decode classes through a
// bounded worker queue, discard failed rows, sort by name/native address, and
// then enrich the surviving records with static-field values.
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
}; // 24bytes
template <class Class> struct Contracts {
    virtual std::uint8_t registry_mode(Address reader) = 0;             // reader8->VMmetadata48
    virtual Read<std::vector<Entry>> walk_mode_one(Address reader) = 0; // kfLE01S58C@1a9fee0
    virtual Read<std::vector<Entry>> walk_mode_two(Address reader) = 0; // vTeJ9wLfhjr@1aa5240
    virtual std::int64_t configured_parallelism() = 0;                  // global5779f74
    virtual Read<Class> collect_class(Address reader, Address klass, Address context,
                                      std::uint8_t) = 0; // 179
    // Recovered: create a channel with capacity 4*workers, launch workers with
    // deferred WaitGroup.Done, send indices 0..n-1, close, and wait. Callbacks
    // write disjoint slots. This contract retains that scheduling
    // boundary because shared evidence-budget allocation can depend on order.
    virtual void indexed_worker_queue(std::size_t count, std::int64_t workers,
                                      std::int64_t capacity,
                                      const std::function<void(std::size_t)> &) = 0;
    virtual void original_bounds_panic() = 0;
    virtual void postprocess_static_fields(Address reader,
                                           std::vector<Class> &) = 0; // iUxOF1vL@1a8d620
};
template <class Class> bool original_less(const Class &a, const Class &b) { // closure1a9f780
    if (a.name == b.name)
        return a.klass < b.klass; // unsigned nativepointer tie-break
    return a.name < b.name;       // Go rawstring lexicographic order
}
template <class Class>
Read<std::vector<Class>> collect(Contracts<Class> &rt, Address reader) { // eigNN1NY@1a9e4a0
    Read<std::vector<Entry>> entries;
    switch (rt.registry_mode(reader)) {
    case 1:
        entries = rt.walk_mode_one(reader);
        break;
    case 2:
        entries = rt.walk_mode_two(reader);
        break;
    default:
        return {{}, {true, "class registry layout unavailable"}};
    }
    if (entries.error.present)
        return {{}, entries.error}; // drop partial returneddata
    if (entries.value.empty())
        return {{}, {true, "HotSpot class registry returned no InstanceKlass addresses"}};
    std::vector<Class> slots(entries.value.size());
    std::vector<std::uint8_t> valid(entries.value.size(), 0);
    const auto workers = std::max(std::int64_t{1}, rt.configured_parallelism());
    rt.indexed_worker_queue(
        entries.value.size(), workers, workers * 4, [&](std::size_t i) { // worker1a9f940
            if (i >= entries.value.size()) {
                rt.original_bounds_panic();
                return;
            }
            const auto &entry = entries.value[i];
            auto result =
                rt.collect_class(reader, entry.klass, entry.raw_context, entry.context_flag);
            if (result.error.present)
                return; // no error aggregation, no outputrow
            if (i >= slots.size() || i >= valid.size()) {
                rt.original_bounds_panic();
                return;
            }
            slots[i] = std::move(result.value);
            valid[i] = 1;
        });
    std::vector<Class> out;
    out.reserve(slots.size());
    for (std::size_t i = 0; i < slots.size(); ++i)
        if (valid[i])
            out.push_back(std::move(slots[i]));
    if (out.empty())
        return {{}, {true, "HotSpot class registry contained no decodable loaded classes"}};
    std::sort(out.begin(), out.end(), original_less<Class>); // Recovered sort is not stable.
    rt.postprocess_static_fields(reader, out);
    return {std::move(out), {}};
}
// Recovered: selector routes cover modes 0, 1, 2, 3, and 255; empty/erroring
// enumeration; total/partial decode failure; minimum worker count; output
// compaction; sorting; and postprocessing. The comparator uses bytewise class
// names and an unsigned native-address tie-break.
// Interpretation: indexed_worker_queue models the observed Go channel/WaitGroup
// schedule boundary, including success-only writes to disjoint slots. It does not
// claim to reproduce the Go scheduler.
} // namespace ocean::reconstructed::minecraft_java_class_registry
