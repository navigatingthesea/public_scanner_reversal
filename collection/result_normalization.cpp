#include "../session/session_types.hpp"
#include <set>
namespace ocean::reconstructed::aggregate_normalization_review {
// Recovered: remove rows containing the exact canary substring, deduplicate, and
// sort string results. Debug interfaces deduplicate by fmt.Sprintf("%v") with the
// last value winning, then sort keys; reflection/formatting failures remain contracts.
constexpr const char *exclusion = "vxGmuhXjgkrLmUmFfourqFOJSQStDV";
bool contains_exclusion(const ByteString &value) {
    return value.find(exclusion) != ByteString::npos;
}
// TZegJu@f361a0: exact case-sensitive substring; no trim or equality test.
// HCZ3Ed@f36380: reject exclusion-containing rows; exact byte-string dedup,
// then original byte-string sort. No case folding or Unicode normalization.
StringList normalize_string_results(const StringList &inputs) {
    std::set<ByteString> found;
    for (const auto &row : inputs.items)
        if (!contains_exclusion(row))
            found.insert(row);
    return {true, std::vector<ByteString>(found.begin(), found.end())};
}
struct GoInterface {
    std::uint64_t type, data;
};
struct InterfaceList {
    bool has_backing_storage = false;
    std::vector<GoInterface> items;
};
struct DebugNormalizationContracts {
    virtual ~DebugNormalizationContracts() = default;
    virtual ByteString original_sprintf_percent_v(GoInterface) = 0;
    virtual ByteString original_reflected_string_field_or_sprint(GoInterface,
                                                                 const ByteString &field) = 0;
};
// Ovn8CoJsB@f36640. The dedup key is fmt.Sprintf("%v", value), not
// serialized JSON and not pointer/object identity. Two different values can
// have the same formatted key; the LAST accepted interface replaces the first.
// First canary test uses that key. The second uses gWaZ0Q(value,"Name").
// Keys are sorted and mapped back to interfaces in that key order.
InterfaceList normalize_debug_results(DebugNormalizationContracts &r, const InterfaceList &inputs) {
    std::map<ByteString, GoInterface> found;
    for (const auto value : inputs.items) {
        const auto key = r.original_sprintf_percent_v(value);
        if (contains_exclusion(key))
            continue;
        const auto name = r.original_reflected_string_field_or_sprint(value, "Name");
        if (!contains_exclusion(name))
            found[key] = value;
    }
    InterfaceList output;
    output.has_backing_storage = true;
    for (const auto &[key, value] : found)
        output.items.push_back(value);
    return output;
}
// gWaZ0Q@f36b40 obtains reflect.ValueOf, unwraps interface/pointer values
// until another kind, returns empty for a nil pointer/interface, then:
// * struct: FieldByName; return its exact string if valid/string kind, else empty
// * other kind: fmt.Sprint(original interface).
// Reflection visibility, pointer cycles, panics, user formatting methods and
// all Go types are not reimplemented here; their exact behavior stays a contract.
// Recovered: GoFq merges globals 0x572e7a0 and 0x572e5e0 before HCZ produces
// WARNINGS; it merges 0x572e8e0 and 0x572e700 before Ovn produces DEBUG_DETECTIONS.
// Evidence:original helper bodies, independently recovered canary,7 original
// normalizer control fixtures with explicit fmt/reflection/map/sort models.
// Review text only; never compiled or executed.
} // namespace ocean::reconstructed::aggregate_normalization_review
