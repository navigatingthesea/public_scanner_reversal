#include "query_records.hpp"
#include <algorithm>
#include <set>

namespace ocean::reconstructed::lua_review {
struct MemoryCallbackContracts {
    using State = std::uint64_t;
    virtual ~MemoryCallbackContracts() = default;
    virtual bool is_table(State, std::int64_t) = 0;
    virtual bool is_number(State, std::int64_t) = 0;
    virtual std::int64_t argument_count(State) = 0;
    virtual std::int64_t to_integer(State, std::int64_t) = 0;
    virtual bool to_boolean(State, std::int64_t) = 0;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual ByteString original_object_to_string(State, std::int64_t) = 0;
    virtual void push_nil(State) = 0;
    virtual bool next(State, std::int64_t table) = 0;
    virtual void pop(State, std::int64_t) = 0;
    virtual void push_boolean(State, bool) = 0;
    virtual std::size_t original_utf8_rune_count(const ByteString&) = 0;
    virtual QueryError collect_original_memory_strings(
        std::uint32_t pid,
        std::int64_t minimum,
        std::int64_t maximum,
        bool memory_type_flag,
        bool character_flag,
        std::vector<ByteString>&) = 0; // TMAnckaH@6ca8c0 -> p1Z80QE@6c9c60
    virtual ByteString original_log_label() = 0; // descriptor 0x3e2be60
    virtual void log_two_values(const ByteString&, const ByteString&) = 0;
};

// @0x1ef2e60
std::int64_t log_callback(
    MemoryCallbackContracts& runtime,
    MemoryCallbackContracts::State state,
    std::int64_t& emitted_bytes) {
    constexpr std::int64_t maximum = 0x80000;
    if (emitted_bytes > 0x7ffff) return 0;

    ByteString line;
    const auto count = runtime.argument_count(state);
    for (std::int64_t index = 1; index <= count; ++index) {
        if (index > 1) line += '\t';
        line += runtime.original_object_to_string(state, index);
    }
    if (line.empty()) return 0;

    const auto remaining = static_cast<std::size_t>(maximum - emitted_bytes);
    if (line.size() > remaining) line.resize(remaining);
    emitted_bytes += static_cast<std::int64_t>(line.size());
    runtime.log_two_values(runtime.original_log_label(), line);
    return 0;
}

// @0x1f36300
std::int64_t memory_strings_callback(
    MemoryCallbackContracts& runtime,
    MemoryCallbackContracts::State state) {
    if (!runtime.is_table(state, 1) || !runtime.is_table(state, 2)) {
        runtime.push_boolean(state, false);
        return 1;
    }
    const bool substring_match = runtime.to_boolean(state, 3);

    std::vector<std::uint32_t> process_ids;
    runtime.push_nil(state);
    while (runtime.next(state, 1)) {
        if (runtime.is_number(state, -1)) {
            const auto process_id =
                static_cast<std::uint32_t>(runtime.to_integer(state, -1));
            if (process_id != 0) process_ids.push_back(process_id);
        }
        runtime.pop(state, 1);
        if (process_ids.size() >= 64) {
            runtime.pop(state, 1); // remaining iteration key
            break;
        }
    }

    std::vector<ByteString> patterns;
    std::set<ByteString> seen;
    runtime.push_nil(state);
    while (runtime.next(state, 2)) {
        const auto pattern = runtime.to_string(state, -1);
        runtime.pop(state, 1);
        if (pattern.size() >= 4 && pattern.size() <= 256 &&
            seen.insert(pattern).second)
            patterns.push_back(pattern);
        if (patterns.size() >= 32) {
            runtime.pop(state, 1);
            break;
        }
    }

    if (process_ids.empty() || patterns.empty()) {
        runtime.push_boolean(state, false);
        return 1;
    }

    std::size_t minimum_runes = 0;
    std::size_t maximum_runes = 0;
    for (const auto& pattern : patterns) {
        const auto count = runtime.original_utf8_rune_count(pattern);
        if (minimum_runes == 0 || minimum_runes > count) minimum_runes = count;
        if (maximum_runes < count) maximum_runes = count;
    }
    minimum_runes = std::max<std::size_t>(minimum_runes, 4);
    maximum_runes = std::min<std::size_t>(maximum_runes, 256);
    if (maximum_runes < minimum_runes) maximum_runes = minimum_runes;

    for (const auto process_id : process_ids) {
        std::vector<ByteString> strings;
        const auto error = runtime.collect_original_memory_strings(
            process_id, minimum_runes, maximum_runes, false, true, strings);
        if (error) continue;

        for (const auto& value : strings) {
            for (const auto& pattern : patterns) {
                const bool matches = substring_match ?
                    value.find(pattern) != ByteString::npos : value == pattern;
                if (matches) {
                    runtime.push_boolean(state, true);
                    return 1;
                }
            }
        }
    }
    runtime.push_boolean(state, false);
    return 1;
}

// Log input values are object-formatted, tab-joined, and capped to 512 KiB per
// closure; byte truncation may split UTF-8. MemStrings accepts at most 64 nonzero
// PIDs and 32 unique 4..256-byte patterns. It derives collector bounds from UTF-8
// rune counts, requests flags (false,true), and returns true on the first exact or
// substring match. Invalid inputs, collection errors, and no match all return false.
}
