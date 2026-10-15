#pragma once
#include "../lua/query_records.hpp"
namespace ocean::reconstructed::install_registry_time_review {
// Recovered: shared return layout for install-time collectors: a three-word Go
// time value followed by a two-word Go error interface.
using ByteString = lua_review::ByteString;
using GoTimeWords = lua_review::GoTimeWords;
struct GoError {
    std::uint64_t type = 0, data = 0;
    explicit operator bool() const { return type != 0; }
};
struct TimeResult {
    GoTimeWords time;
    GoError error;
}; // 40 original bytes
} // namespace ocean::reconstructed::install_registry_time_review
