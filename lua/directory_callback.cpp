#include "query_records.hpp"

namespace ocean::reconstructed::lua_review {
struct NamePathRecord {
    ByteString name;
    ByteString path;
}; // types 0x366b660/0x366b700, 32 bytes

struct DirectoryCallbackContracts {
    using State = std::uint64_t;
    using Entry = std::uint64_t;
    struct Share {
        ByteString name;
        ByteString unc_path;
    };

    virtual ~DirectoryCallbackContracts() = default;
    virtual ByteString to_string(State, std::int64_t) = 0;
    virtual ByteString trim_space(const ByteString&) = 0;
    virtual ByteString path_argument(State, std::int64_t) = 0;
    virtual bool original_server_request_predicate(const ByteString&) = 0; // hSPLN1@1ef9c60
    virtual QueryError original_parse_server(
        const ByteString&,
        ByteString&) = 0; // cgHbTV@1ef8d80
    virtual QueryError enumerate_shares(
        const ByteString& server,
        std::vector<Share>&) = 0; // zb6pDr
    virtual QueryError read_directory(
        const ByteString& path,
        std::vector<Entry>&) = 0; // os.BcOPDsK
    virtual bool is_directory(Entry) = 0;
    virtual ByteString name(Entry) = 0;
    virtual ByteString join_path(const ByteString&, const ByteString&) = 0;
    virtual std::int64_t push_original_name_path_records(
        State,
        const std::vector<NamePathRecord>&,
        bool original_share_type) = 0;
    virtual std::int64_t push_original_directory_error(
        State,
        unsigned branch,
        const QueryError&) = 0;
};

// @0x1f20540
std::int64_t get_files_callback(
    DirectoryCallbackContracts& runtime,
    DirectoryCallbackContracts::State state) {
    const auto input = runtime.trim_space(runtime.to_string(state, 1));
    if (runtime.original_server_request_predicate(input)) {
        ByteString server;
        auto error = runtime.original_parse_server(input, server);
        if (error) return runtime.push_original_directory_error(state, 0, error);

        std::vector<DirectoryCallbackContracts::Share> shares;
        error = runtime.enumerate_shares(server, shares);
        if (error) return runtime.push_original_directory_error(state, 1, error);

        std::vector<NamePathRecord> rows;
        rows.reserve(shares.size());
        for (const auto& share : shares)
            rows.push_back({share.name, share.unc_path});
        return runtime.push_original_name_path_records(state, rows, true);
    }

    const auto path = runtime.path_argument(state, 1);
    std::vector<DirectoryCallbackContracts::Entry> entries;
    const auto error = runtime.read_directory(path, entries);
    if (error) return runtime.push_original_directory_error(state, 2, error);

    std::vector<NamePathRecord> rows;
    rows.reserve(entries.size());
    for (const auto entry : entries) {
        if (runtime.is_directory(entry)) continue;
        const auto entry_name = runtime.name(entry);
        rows.push_back({entry_name, runtime.join_path(path, entry_name)});
    }
    return runtime.push_original_name_path_records(state, rows, false);
}

// Input: one path-like string. Server-shaped input is parsed and returns share
// name/UNC-path records. Other input is normalized by path_argument, reads one
// directory, excludes every subdirectory, and returns file name/full-path rows.
// Parse, share enumeration, and directory-read failures use branches 0, 1, and 2.
}
