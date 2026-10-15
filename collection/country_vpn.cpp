#include "../lua/query_records.hpp"
#include <functional>
namespace ocean::reconstructed::country_vpn_review {
// Recovered: fetch the public IP, query proxycheck.io, inspect the first nested
// map encountered in Go map-iteration order, and return its string country/proxy
// fields. Any HTTP/read/JSON failure or recovered panic returns Unknown/Unknown.
using ByteString = lua_review::ByteString;
using Error = lua_review::QueryError;
struct CountryVpn {
    ByteString country = "Unknown", vpn = "Unknown";
};
struct GoObject {
    std::uint64_t original_type = 0, data = 0;
};
constexpr std::uint64_t map_string_any_type_rva = 0x3639a80, string_type_rva = 0x3588fa0;
struct CountryContracts {
    using Channel = std::uint64_t;
    using Client = std::uint64_t;
    using Body = std::uint64_t;
    using GoMap = std::uint64_t;
    struct Response {
        Body body = 0;
    };
    struct Panic {
        std::uint64_t type = 0, data = 0;
    };
    struct Defers {
        virtual ~Defers() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~CountryContracts() = default;
    virtual CountryVpn original_timed_pair_scope(const std::function<CountryVpn()> &) = 0;
    virtual Channel buffered_pair_channel(std::size_t) = 0;
    virtual void spawn_goroutine(const std::function<void()> &) = 0;
    virtual CountryVpn receive_pair(Channel) = 0;
    virtual void send_pair(Channel, const CountryVpn &) = 0;
    // Runs body-close defers LIFO on normal return or Go panic; then calls the
    // original recover handler for a recovered nonnil panic, including close panic.
    virtual void original_worker_recovery_scope(const std::function<void(Defers &)> &,
                                                const std::function<void(Panic)> &) = 0;
    virtual void log_original_recovered_panic(const ByteString &label, Panic) = 0;
    virtual Client original_http_client(
        std::int64_t timeout_ns) = 0; // HoHxz_Mz: transport setup remains a dependency
    virtual Error http_get(Client, const ByteString &url, Response &) = 0;
    virtual void close_body(Body) = 0;
    virtual Error original_read_all_after_reader_assertion(Body, std::vector<std::uint8_t> &) = 0;
    virtual ByteString original_trim_space(const ByteString &) = 0;
    virtual Error json_unmarshal_map_string_any(const std::vector<std::uint8_t> &, GoMap &) = 0;
    // Original Go map iteration order, stopping immediately when visitor returns
    // true. The outer JSON key is ignored; this does not look up the requested IP.
    virtual void visit_map_values_until(GoMap, const std::function<bool(GoObject)> &visitor) = 0;
    virtual GoObject map_lookup_string_any(GoMap, const ByteString &key) = 0;
    virtual bool has_exact_original_type(GoObject, std::uint64_t type_rva) = 0;
    virtual ByteString unbox_original_string(GoObject) = 0;
};
// Worker@f30140; recover@f308a0; close wrappers@f30860/f30820.
void country_vpn_worker(CountryContracts &r, CountryContracts::Channel channel) {
    r.original_worker_recovery_scope(
        [&](CountryContracts::Defers &defers) {
            const auto client = r.original_http_client(30000000000LL);
            CountryContracts::Response ip_response;
            if (r.http_get(client, "https://ifconfig.me/ip", ip_response)) {
                r.send_pair(channel, {});
                return;
            }
            defers.add([&r, body = ip_response.body] { r.close_body(body); });
            std::vector<std::uint8_t> ip_bytes;
            if (r.original_read_all_after_reader_assertion(ip_response.body, ip_bytes)) {
                r.send_pair(channel, {});
                return;
            }
            const auto ip = r.original_trim_space(ByteString(ip_bytes.begin(), ip_bytes.end()));
            const auto url = "https://proxycheck.io/v2/" + ip + "?vpn=1&asn=1";
            CountryContracts::Response lookup_response;
            if (r.http_get(client, url, lookup_response)) {
                r.send_pair(channel, {});
                return;
            }
            defers.add([&r, body = lookup_response.body] { r.close_body(body); });
            std::vector<std::uint8_t> json;
            if (r.original_read_all_after_reader_assertion(lookup_response.body, json)) {
                r.send_pair(channel, {});
                return;
            }
            CountryContracts::GoMap response_map = 0;
            if (r.json_unmarshal_map_string_any(json, response_map)) {
                r.send_pair(channel, {});
                return;
            }
            CountryVpn result;
            r.visit_map_values_until(response_map, [&](GoObject value) {
                if (!r.has_exact_original_type(value, map_string_any_type_rva))
                    return false;
                const auto country = r.map_lookup_string_any(value.data, "country");
                const auto proxy = r.map_lookup_string_any(value.data, "proxy");
                if (r.has_exact_original_type(country, string_type_rva))
                    result.country = r.unbox_original_string(country);
                if (r.has_exact_original_type(proxy, string_type_rva))
                    result.vpn = r.unbox_original_string(proxy);
                return true; // first nested map, even if both fields are absent/non-string
            });
            r.send_pair(channel, result); // HTTP status and API status fields are not checked here
        },
        [&](CountryContracts::Panic panic) {
            r.log_original_recovered_panic("Country", panic);
            r.send_pair(channel, {});
        });
}
// Outer@f2ffa0: timed, buffered channel1, one worker and one receive.
CountryVpn collect_country_vpn(CountryContracts &r) {
    return r.original_timed_pair_scope([&] {
        const auto channel = r.buffered_pair_channel(1);
        r.spawn_goroutine([&r, channel] { country_vpn_worker(r, channel); });
        return r.receive_pair(channel);
    });
}
} // namespace ocean::reconstructed::country_vpn_review
