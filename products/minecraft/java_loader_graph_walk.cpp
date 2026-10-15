#include "../../session/session_types.hpp"
#include <optional>
#include <unordered_set>
#include <vector>
namespace ocean::reconstructed::minecraft_java_loader_graph_walk {
// Recovered: registry mode 1 walks ClassLoaderDataGraph, then each loader's
// linked Klass list. raw_context is the ClassLoaderData address and context_flag
// records the recovered bootstrap-loader classification.
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
    virtual std::optional<Address> vm_field(Address reader, const ByteString &type,
                                            const ByteString &member) = 0;
    virtual Read<Address> read_pointer(Address) = 0;
    virtual Error wrap_error(const ByteString &format, const Error &) = 0;
};
Read<std::vector<Entry>> collect(Contracts &rt, Address reader) { // kfLE01S58C@1a9fee0,mode1
    const auto head = rt.vm_field(reader, "ClassLoaderDataGraph", "_head");
    const auto next_loader = rt.vm_field(reader, "ClassLoaderData", "_next");
    const auto classes = rt.vm_field(reader, "ClassLoaderData", "_klasses");
    const auto next_class = rt.vm_field(reader, "Klass", "_next_link");
    if (!head || !next_loader || !classes || !next_class)
        return {{}, {true, "ClassLoaderDataGraph layout incomplete"}};
    const auto first = rt.read_pointer(*head);
    if (first.error.present)
        return {{}, rt.wrap_error("read ClassLoaderDataGraph head: %w", first.error)};
    Address null_loader = 0;
    if (const auto address =
            rt.vm_field(reader, "ClassLoaderDataGraph", "_the_null_class_loader_data"))
        null_loader = rt.read_pointer(*address).value; // errorignored; keepreturnedvalue
    const auto class_loader = rt.vm_field(reader, "ClassLoaderData", "_class_loader");
    std::vector<Entry> out;
    out.reserve(65536);
    std::unordered_set<Address> seen_loaders, seen_classes;
    Address loader = first.value;
    while (loader && seen_loaders.size() < 2000000) {
        if (!seen_loaders.insert(loader).second)
            break;
        bool bootstrap = false;
        if (null_loader)
            bootstrap = loader == null_loader;
        else if (class_loader) {
            const auto handle = rt.read_pointer(loader + *class_loader);
            bootstrap = !handle.error.present && handle.value == 0;
        }
        const auto first_class = rt.read_pointer(loader + *classes);
        if (first_class.error.present)
            break; // stopENTIREwalk,retainrows,nilerror
        Address klass = first_class.value;
        for (std::uint32_t steps = 0; klass && steps < 2000000; ++steps) {
            if (!seen_classes.insert(klass).second)
                break; // globalacrossloaders
            out.push_back({klass, loader, static_cast<std::uint8_t>(bootstrap)});
            const auto next = rt.read_pointer(klass + *next_class);
            if (next.error.present)
                break; // Stop this class chain, then continue with the next loader.
            klass = next.value;
        }
        const auto next = rt.read_pointer(loader + *next_loader);
        if (next.error.present)
            break; // Retain partial rows and return no top-level error.
        loader = next.value;
    }
    return {std::move(out), {}};
}
// Recovered: 25 routes cover missing layouts, head-read failure, both bootstrap
// classification methods, global class deduplication, cycles, and partial-read
// behavior. Failure to read a loader's first class stops the whole walk; failure
// inside a class chain advances to the next loader. A loader-link failure returns
// accumulated rows without a top-level error.
// Interpretation: both two-million-entry limits are runaway guards.
} // namespace ocean::reconstructed::minecraft_java_loader_graph_walk
