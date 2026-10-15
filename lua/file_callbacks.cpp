#include "query_records.hpp"
#include <cstring>

namespace ocean::reconstructed::lua_review {
std::int64_t original_unix_seconds(GoTimeWords);

struct FileInfoRecord { // Go type 0x3793e60, 184 bytes
    ByteString name;
    ByteString path;
    ByteString extension;
    std::int64_t size = 0;
    bool dir = false;
    ByteString attributes;
    ByteString created;
    ByteString modified;
    ByteString accessed;
    std::int64_t created_ts = 0;
    std::int64_t modified_ts = 0;
    std::int64_t accessed_ts = 0;
    ByteString sha256;
    ByteString md5;
};
struct HashFileMap {
    ByteString Path;
    std::int64_t Size = 0;
    ByteString SHA256;
    ByteString MD5;
};

struct FileCallbackContracts {
    using State = std::uint64_t;
    using Stat = std::uint64_t;
    struct WindowsAttributes {
        std::uint32_t attributes = 0;
        std::uint32_t creation_low = 0;
        std::uint32_t creation_high = 0;
        std::uint32_t access_low = 0;
        std::uint32_t access_high = 0;
    };

    virtual ~FileCallbackContracts() = default;
    virtual ByteString path_argument(State, std::int64_t) = 0;
    virtual QueryError stat_file(const ByteString&, Stat&) = 0;
    virtual GoTimeWords modification_time(Stat) = 0;
    virtual bool exact_windows_attributes(Stat, WindowsAttributes&) = 0; // type 0x3532300
    virtual std::uint64_t original_local_zone() = 0; // global 0x565c808
    virtual ByteString windows_attribute_string(std::uint32_t) = 0; // h2m8Gy
    virtual ByteString name(Stat) = 0;
    virtual std::int64_t size(Stat) = 0;
    virtual bool is_directory(Stat) = 0;
    virtual ByteString original_file_time_format(
        unsigned layout_index,
        GoTimeWords) = 0;
    virtual bool original_sha256_md5(
        const ByteString& path,
        ByteString& sha256,
        ByteString& md5) = 0; // zAXA4UrJtG
    virtual std::int64_t push_file_info(State, const FileInfoRecord&) = 0;
    virtual std::int64_t push_original_hash_map(State, const HashFileMap&) = 0;
    virtual std::int64_t push_original_file_error(
        State,
        std::uint32_t original_callback,
        unsigned branch,
        const QueryError&,
        const ByteString& path,
        std::int64_t size) = 0;
};

GoTimeWords original_filetime_to_go_time(
    std::uint32_t low,
    std::uint32_t high,
    std::uint64_t local_zone) {
    // Recovered: uint64 overflow occurs before converting to time.Time words.
    const auto bits = ((std::uint64_t{high} << 32) | low) * 100 +
        UINT64_C(0x5e6684f4b3960000);
    std::int64_t seconds = 0;
    std::uint64_t fractional = bits;
    if (bits >= 1000000000) {
        std::int64_t nanoseconds;
        std::memcpy(&nanoseconds, &bits, 8);
        seconds = nanoseconds / 1000000000;
        auto remainder = nanoseconds % 1000000000;
        if (remainder < 0) {
            remainder += 1000000000;
            --seconds;
        }
        fractional = static_cast<std::uint64_t>(remainder);
    }

    const auto extended_bits =
        static_cast<std::uint64_t>(seconds) + UINT64_C(0xe7791f700);
    std::int64_t extended;
    std::memcpy(&extended, &extended_bits, 8);
    return {static_cast<std::uint32_t>(fractional), extended, local_zone};
}

ByteString extension_of_original_file_name(const ByteString& name) {
    for (std::size_t position = name.size(); position > 0; --position) {
        const char byte = name[position - 1];
        if (byte == '\\' || byte == '/') break;
        if (byte == '.') return name.substr(position - 1);
    }
    return {};
}

// @0x1f40b60
std::int64_t file_info_callback(
    FileCallbackContracts& runtime,
    FileCallbackContracts::State state) {
    const auto path = runtime.path_argument(state, 1);
    FileCallbackContracts::Stat stat = 0;
    const auto error = runtime.stat_file(path, stat);
    if (error)
        return runtime.push_original_file_error(
            state, 0x1f40b60, 0, error, path, 0);

    auto created = runtime.modification_time(stat);
    auto accessed = runtime.modification_time(stat);
    FileCallbackContracts::WindowsAttributes native;
    ByteString attributes;
    if (runtime.exact_windows_attributes(stat, native)) {
        created = original_filetime_to_go_time(
            native.creation_low, native.creation_high, runtime.original_local_zone());
        accessed = original_filetime_to_go_time(
            native.access_low, native.access_high, runtime.original_local_zone());
        attributes = runtime.windows_attribute_string(native.attributes);
    }

    // Recovered: repeat FileInfo method calls in the observed order.
    FileInfoRecord row;
    row.name = runtime.name(stat);
    row.extension = extension_of_original_file_name(runtime.name(stat));
    row.path = path;
    row.size = runtime.size(stat);
    row.dir = runtime.is_directory(stat);
    row.attributes = attributes;
    row.created = runtime.original_file_time_format(0, created);
    row.modified = runtime.original_file_time_format(1, runtime.modification_time(stat));
    row.accessed = runtime.original_file_time_format(2, accessed);
    row.created_ts = original_unix_seconds(created);
    row.modified_ts = original_unix_seconds(runtime.modification_time(stat));
    row.accessed_ts = original_unix_seconds(accessed);

    if (!runtime.is_directory(stat) && runtime.size(stat) <= INT64_C(0x40000000)) {
        ByteString sha256;
        ByteString md5;
        if (runtime.original_sha256_md5(path, sha256, md5)) {
            row.sha256 = sha256;
            row.md5 = md5;
        }
    }
    return runtime.push_file_info(state, row);
}

// @0x1f42740
std::int64_t hash_file_callback(
    FileCallbackContracts& runtime,
    FileCallbackContracts::State state) {
    const auto path = runtime.path_argument(state, 1);
    FileCallbackContracts::Stat stat = 0;
    const auto error = runtime.stat_file(path, stat);
    if (error)
        return runtime.push_original_file_error(
            state, 0x1f42740, 0, error, path, 0);
    if (runtime.is_directory(stat))
        return runtime.push_original_file_error(
            state, 0x1f42740, 1, {}, path, 0);
    if (runtime.size(stat) > INT64_C(0x200000000))
        return runtime.push_original_file_error(
            state, 0x1f42740, 2, {}, path, runtime.size(stat));

    HashFileMap result;
    result.Path = path;
    if (!runtime.original_sha256_md5(path, result.SHA256, result.MD5))
        return runtime.push_original_file_error(
            state, 0x1f42740, 3, {}, path, 0);
    result.Size = runtime.size(stat);
    return runtime.push_original_hash_map(state, result);
}

// FileInfo emits metadata and hashes regular files up to 1 GiB; hash failures
// merely leave omitempty digest fields blank. HashFile rejects directories and
// files above 8 GiB, requires both SHA256 and MD5, and emits exact map keys
// Path/Size/SHA256/MD5. Its four failure templates are branches 0..3.
}
