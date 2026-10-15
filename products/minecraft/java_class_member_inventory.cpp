#include "../../session/session_types.hpp"
#include <unordered_map>
#include <set>
namespace ocean::reconstructed::minecraft_class_member_inventory_review {
// Recovered: cache the complete native class slice per PID, then project class
// names and member names into the map consumed by higher-level Java checks.
// This cache contains all recovered classes for the PID; it is not a fixed list
// of six monitored classes.
struct ErrorWords {
    std::uint64_t type = 0, data = 0;
    bool present() const { return type != 0; }
};
struct RawClassSlice {
    std::uint64_t original_data = 0;
    GoInt length = 0, capacity = 0;
};
struct ClassResult {
    RawClassSlice value;
    ErrorWords error;
};
struct CacheContracts {
    virtual void original_class_cache_mutex_lock() = 0; // 577a598
    virtual void original_class_cache_mutex_unlock() = 0;
    virtual ErrorWords original_error_string(const ByteString &) = 0;
    virtual ClassResult original_native_class_collection(std::uint32_t pid) = 0; // oyNLd5KBviAK
};
using PidCache = std::unordered_map<std::uint32_t, RawClassSlice>; // global5729220
// HwpIX6AeeIx@1a8b060. Key type is captured uint32, not process creation time.
// Hits include successful empty/nil class slices. No expiry/refresh check here.
ClassResult cached_pid_classes(CacheContracts &r, PidCache &cache, std::uint32_t pid) {
    if (pid == 0)
        return {{}, r.original_error_string("hotspot: pid must be non-zero")};
    r.original_class_cache_mutex_lock();
    const auto found = cache.find(pid);
    if (found != cache.end()) {
        const auto result = found->second;
        r.original_class_cache_mutex_unlock();
        return {result, {}};
    }
    r.original_class_cache_mutex_unlock();
    const auto collected = r.original_native_class_collection(pid);
    if (collected.error.present())
        return {{}, collected.error};
    r.original_class_cache_mutex_lock();
    cache[pid] = collected.value;
    r.original_class_cache_mutex_unlock();
    return collected;
}
// The mutex is released during collection. This code does not add a second
// lookup after collection; concurrent misses may both collect and overwrite.
// Actual contention/panic/defer/recovery is an original runtime contract.

struct NameContracts {
    virtual ByteString original_unicode_lowercase(const ByteString &) = 0;
};
// Recovered gOg82XwmVbhb@1a92040: all 23 prefix comparisons from the original
// loop (bound 0x17), followed by two substring tests. Prefixes lack a component
// boundary unless the literal includes a trailing dot. No slash conversion.
bool excluded_from_class_member_map(NameContracts &r, const ByteString &name) {
    const auto lower = r.original_unicode_lowercase(name);
    for (const auto prefix : {"com.sun",
                              "com.llamalad7",
                              "sun.util",
                              "com.modrinth",
                              "net.minecraft.",
                              "java.nio",
                              "com.mojang",
                              "io.netty",
                              "java.lang.",
                              "jdk.internal",
                              "org.apache",
                              "org.lwjgl",
                              "org.objectweb",
                              "org.spongepowered",
                              "sun.net",
                              "sun.security",
                              "com.google",
                              "net.caffeinemc",
                              "net.fabricmc",
                              "dev.isxander.debugify",
                              "dev.terminalmc.chatnotify",
                              "com.viaversion",
                              "com.moulberry"}) {
        const ByteString literal = prefix;
        if (lower.size() >= literal.size() && lower.compare(0, literal.size(), literal) == 0)
            return true;
    }
    return lower.find("lunarclient") != ByteString::npos ||
           lower.find("badlion") != ByteString::npos;
}
// Recovered projection of a 320-byte class record: name words 0/8 and member
// slice words 16/24/32. The full native record also
// has additional fields that this projection does not read or serialize.
// The original member field at offset 16 has json:"-" in its struct, but Qwx deliberately
// copies it into a new map[string][]string, which Qc separately serializes.
struct ClassMemberProjection {
    ByteString name;
    std::vector<ByteString> members;
};
struct MemberList {
    bool has_backing_storage = true;
    std::vector<ByteString> values;
};
using MemberMap = std::unordered_map<ByteString, MemberList>;
// Qwx4ImO@1a95b20: skip empty/excluded names, group by EXACT full name,
// discard empty member names, deduplicate exact strings, sort bytes per value.
// Distinct full names sharing a simple name remain distinct keys.
MemberMap class_member_map(NameContracts &r, const std::vector<ClassMemberProjection> &records) {
    std::unordered_map<ByteString, std::set<ByteString>> groups;
    for (const auto &record : records) {
        if (record.name.empty() || excluded_from_class_member_map(r, record.name))
            continue;
        auto &names = groups[record.name];
        for (const auto &member : record.members)
            if (!member.empty())
                names.insert(member);
    }
    MemberMap result;
    for (const auto &pair : groups) {
        MemberList list;
        list.values.assign(pair.second.begin(), pair.second.end());
        result.emplace(pair.first, std::move(list)); // empty group produces nonnil []
    }
    return result;
}
// Recovered: ZQPDWj@1a96060 obtains the cached raw slice. Collection failure
// returns a nil map plus error; success projects every 320-byte class record.
struct ProjectContracts {
    virtual std::vector<ClassMemberProjection>
    original_project_name_and_members(const RawClassSlice &) = 0;
};
// Recovered: cache and aggregation paths validate the 320-byte record stride and
// every prefix boundary. Unicode lowercasing remains a provider contract because
// the controlled boundary inputs were ASCII.
} // namespace ocean::reconstructed::minecraft_class_member_inventory_review
