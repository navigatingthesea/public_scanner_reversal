#include "../../common/review_contracts.hpp"
#include <vector>
#include <map>
namespace ocean::reconstructed {
// Recovered: read Discord stable and Canary scope_v3.json files from APPDATA,
// keep records with nonempty user ID and username, then emit indented JSON in
// source order. Open/decode failures skip one file; marshal failure returns empty.
using JsonBytes = std::vector<std::uint8_t>;
struct DiscordScopeUser {
    ByteString id, username, email;
};
struct DiscordMetadataContracts {
    struct File {
        std::uint64_t opaque;
    };
    virtual ~DiscordMetadataContracts() = default;
    virtual void register_defer_descriptor(std::uint64_t rva) = 0;
    virtual void register_timing_defer() = 0;
    virtual ByteString environment(const ByteString &) = 0;
    virtual ByteString windows_join(const std::vector<ByteString> &) = 0;
    virtual bool open_readonly(const ByteString &, File &) = 0;
    virtual bool decode_scope_user_json(File, DiscordScopeUser &) = 0;
    virtual void close_file(File) = 0;
    virtual bool marshal_indented(const std::vector<std::map<ByteString, ByteString>> &,
                                  const ByteString &prefix, const ByteString &indent,
                                  JsonBytes &) = 0;
    virtual void log_collection_failure(std::uint64_t original_branch_rva) = 0;
    virtual void run_registered_defers_now() = 0;
    virtual void final_collection_hook() = 0; // CquUUoEr5_a5.D4rvKAG2Qu @0x6cfc20
};
// UAy9caHUbZ.Id4KMAaH @0xf1f740. Decoded schema is scope.user with
// id/username/email fields. Only id and username are emitted. Preserve both
// stable/Canary records and duplicates; this collector does not deduplicate.
JsonBytes collect_discord_scope_metadata(DiscordMetadataContracts &r) {
    r.register_defer_descriptor(0x3dfe438);
    r.register_timing_defer();
    const auto appdata = r.environment("APPDATA");
    const auto stable = r.windows_join({appdata, "discord", "sentry", "scope_v3.json"});
    const auto canary = r.windows_join({appdata, "discordcanary", "sentry", "scope_v3.json"});
    std::vector<std::map<ByteString, ByteString>> records;
    for (const auto &path : {stable, canary}) {
        DiscordMetadataContracts::File file;
        if (!r.open_readonly(path, file))
            continue;
        DiscordScopeUser user;
        const bool decoded = r.decode_scope_user_json(file, user);
        // Original closes the file before checking decoded field lengths and also
        // closes on decode failure. File-close errors are discarded.
        if (file.opaque != 0)
            r.close_file(file);
        if (decoded && !user.id.empty() && !user.username.empty())
            records.push_back({{"username", user.username}, {"id", user.id}});
    }
    JsonBytes result;
    if (!records.empty()) {
        if (!r.marshal_indented(records, "", "  ", result)) {
            r.log_collection_failure(0xf21b91);
            result.clear();
        }
    } else {
        r.log_collection_failure(0xf223e7);
    }
    r.run_registered_defers_now();
    r.final_collection_hook();
    return result;
}
} // namespace ocean::reconstructed
