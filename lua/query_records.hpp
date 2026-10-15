#pragma once
#include "captured_lua_environment.hpp"
#include <optional>

namespace ocean::reconstructed::lua_review {
using QueryError = std::optional<ByteString>;

struct ProcessRecord { // Go type @0x3778a60, 96 bytes
    std::int32_t pid = 0;
    std::int32_t ppid = 0;
    ByteString name;
    ByteString exe;
    ByteString cmdline;
    ByteString user;
    ByteString created;
    std::int64_t timestamp = 0;
};

struct RegistryValueRecord { // @0x374a380, 56 bytes
    ByteString name;
    std::uint32_t type = 0;
    ByteString type_name;
    std::uint64_t original_go_interface_type = 0;
    std::uint64_t original_go_interface_data = 0;
};

struct TimeRecord { // @0x377e260, 88 bytes
    std::int64_t timestamp = 0;
    ByteString datetime;
    ByteString rfc3339;
    std::int64_t year = 0;
    std::int64_t month = 0;
    std::int64_t day = 0;
    std::int64_t hour = 0;
    std::int64_t minute = 0;
    std::int64_t second = 0;
};

// Logical time.Time words; this is not std::chrono or a binary-compatible C++ type.
struct GoTimeWords {
    std::uint64_t wall = 0;
    std::int64_t ext = 0;
    std::uint64_t location = 0;
};
}
