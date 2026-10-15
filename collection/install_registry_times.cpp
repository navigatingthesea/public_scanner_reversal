#include "install_time_native_types.hpp"
#include <cstring>
#include <functional>
namespace ocean::reconstructed::install_registry_time_review {
// Recovered: read InstallTime or InstallDate from the Windows CurrentVersion key
// and convert FILETIME ticks or Unix seconds into the original Go time words.
// Registry/type/range failures propagate through TimeResult.
struct RegistryTimeContracts {
    using Key = std::uint64_t;
    struct Defers {
        virtual ~Defers() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~RegistryTimeContracts() = default;
    virtual TimeResult original_go_defer_scope(const std::function<TimeResult(Defers &)> &) = 0;
    virtual GoError open_key(std::uint64_t hive, const ByteString &path, std::uint32_t access,
                             Key &) = 0;
    virtual GoError integer_value(Key, const ByteString &name, std::uint64_t &value,
                                  std::uint32_t &kind) = 0;
    virtual void close_key(Key) = 0;
    virtual std::uint64_t original_local_location() = 0; // global565c808
    virtual std::uint64_t original_utc_location() = 0;   // captured568a060
};
std::int64_t signed_bits(std::uint64_t bits) {
    std::int64_t value = 0;
    std::memcpy(&value, &bits, sizeof value);
    return value;
}
std::uint64_t canonical_location(RegistryTimeContracts &r) {
    const auto location = r.original_local_location();
    return location == r.original_utc_location() ? 0 : location;
}
// xaHr9b@f2c560: unsignedFILETIME threshold, then arithmetic wraps at64bits.
GoTimeWords install_filetime_to_go_time(RegistryTimeContracts &r, std::uint64_t ticks) {
    const auto location = canonical_location(r);
    constexpr std::uint64_t epoch_ticks = 116444736000000000ULL;
    if (ticks < epoch_ticks)
        return {0, 0, location}; // Go zeroTime with possiblynonnull location
    const auto nanoseconds = signed_bits((ticks - epoch_ticks) * 100ULL);
    auto seconds = nanoseconds / 1000000000LL;
    auto nanos = nanoseconds % 1000000000LL;
    if (nanos < 0) {
        nanos += 1000000000LL;
        --seconds;
    } // floornormalization, not truncating negative remainder
    const auto ext = signed_bits(std::uint64_t(seconds) + 0xe7791f700ULL);
    return {std::uint64_t(nanos), ext, location};
}
TimeResult read_install_integer(RegistryTimeContracts &r, const ByteString &name, bool filetime) {
    return r.original_go_defer_scope([&](RegistryTimeContracts::Defers &defers) -> TimeResult {
        RegistryTimeContracts::Key key = 0;
        const auto opened =
            r.open_key(0x80000002, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0x20019, key);
        if (opened)
            return {{}, opened};
        defers.add([&r, key] { r.close_key(key); });
        std::uint64_t value = 0;
        std::uint32_t kind = 0;
        const auto error = r.integer_value(key, name, value, kind);
        if (error)
            return {{}, error};
        if (filetime)
            return {install_filetime_to_go_time(r, value), {}};
        // azmMzikBOI@f2be20, Unix seconds. Resultkind is not checked here.
        return {{0, signed_bits(value + 0xe7791f700ULL), canonical_location(r)}, {}};
    });
}
TimeResult registry_install_time(RegistryTimeContracts &r) {
    return read_install_integer(r, "InstallTime", true);
}
TimeResult registry_install_date(RegistryTimeContracts &r) {
    return read_install_integer(r, "InstallDate", false);
}
} // namespace ocean::reconstructed::install_registry_time_review
