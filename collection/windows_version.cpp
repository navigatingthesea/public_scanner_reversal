#include "../lua/query_records.hpp"
#include <functional>
namespace ocean::reconstructed::windows_version_review {
// Recovered: read ProductName and build/release values from CurrentVersion,
// relabel Windows 10 as Windows 11 for build >=22000, and return one display
// string. Registry-open/ProductName failure or recovered panic returns "Windows ?".
using ByteString = lua_review::ByteString;
using Error = lua_review::QueryError;
struct VersionContracts {
    using Channel = std::uint64_t;
    using Key = std::uint64_t;
    struct RecoveredPanic {
        std::uint64_t original_type = 0, original_data = 0;
    };
    struct Defers {
        virtual ~Defers() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~VersionContracts() = default;
    virtual ByteString
    original_timed_string_scope(const std::function<ByteString()> &) = 0; // HNib.J4zzlapPd.func8
    virtual Channel buffered_string_channel(std::size_t capacity) = 0;
    virtual void spawn_goroutine(const std::function<void()> &) = 0;
    virtual ByteString receive_string(Channel) = 0;
    virtual void send_string(Channel, const ByteString &) = 0;
    // Runs key-close defers before the original outer recover callback. A nonnil
    // recovered panic is logged and sends Windows ?. No channel close is added.
    virtual void original_worker_recovery_scope(const std::function<void(Defers &)> &,
                                                const std::function<void(RecoveredPanic)> &) = 0;
    virtual void log_original_recovered_panic(const ByteString &label, RecoveredPanic) = 0;
    virtual Error open_registry_key(std::uint64_t hive, const ByteString &path,
                                    std::uint32_t access, Key &) = 0;
    virtual void close_registry_key(Key) = 0; // syscall.GGFDmhN68P @worker.deferwrap1
    virtual Error registry_string(Key, const ByteString &name, ByteString &) = 0;
    virtual Error parse_original_decimal_build(const ByteString &,
                                               std::int64_t &) = 0; // cGiRaNV.H4DdklVY4xJ
};
ByteString replace_windows_10_label(ByteString product) {
    const ByteString old = "Windows 10", replacement = "Windows 11";
    std::size_t at = 0;
    while ((at = product.find(old, at)) != ByteString::npos) {
        product.replace(at, old.size(), replacement);
        at += replacement.size();
    }
    return product; // strings.Replace(...,-1), exact case, no trimming
}
// Worker@f38e60, recover@f3a940, key-close defer@f3a900.
void windows_version_worker(VersionContracts &r, VersionContracts::Channel channel) {
    r.original_worker_recovery_scope(
        [&](VersionContracts::Defers &defers) {
            VersionContracts::Key key = 0;
            if (r.open_registry_key(0x80000002, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                    1, key)) {
                r.send_string(channel, "Windows ?");
                return;
            }
            defers.add([&r, key] { r.close_registry_key(key); });
            ByteString product;
            if (r.registry_string(key, "ProductName", product)) {
                r.send_string(channel, "Windows ?");
                return;
            }
            ByteString build_text;
            if (!r.registry_string(key, "CurrentBuildNumber", build_text)) {
                std::int64_t build = 0;
                if (!r.parse_original_decimal_build(build_text, build) && build >= 22000)
                    product = replace_windows_10_label(product);
            }
            ByteString release;
            if (!r.registry_string(key, "DisplayVersion", release)) {
                r.send_string(channel, product + " " + release);
                return;
            }
            if (!r.registry_string(key, "ReleaseId", release)) {
                r.send_string(channel, product + " " + release);
                return;
            }
            r.send_string(channel, product);
        },
        [&](VersionContracts::RecoveredPanic panic) {
            r.log_original_recovered_panic("GetWindowsVersion", panic);
            r.send_string(channel, "Windows ?");
        });
}
// Outer@f38780: one worker and one receive, no timeout or forced channel close.
ByteString collect_windows_version(VersionContracts &r) {
    return r.original_timed_string_scope([&] {
        const auto channel = r.buffered_string_channel(1);
        r.spawn_goroutine([&r, channel] { windows_version_worker(r, channel); });
        return r.receive_string(channel);
    });
}
} // namespace ocean::reconstructed::windows_version_review
