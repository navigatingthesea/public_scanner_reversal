#include "../../session/session_types.hpp"
#include <array>
#include <functional>
namespace ocean::reconstructed::minecraft_review {
// Purpose: select a non-local established TCP endpoint for Minecraft's default
// port and optionally compare a domain against the Windows DNS cache.
struct ParsedIP16 {
  bool valid = false;
  std::array<std::uint8_t, 16> bytes{};
};
struct IpContracts {
  virtual ~IpContracts() = default;
  virtual ParsedIP16 original_parse_ip_16(const ByteString &) = 0;
};
// Recovered (gKUdZHIZpX.iMEpXXFS@1c4b3c0): original IPv4-mapped representation
// and loopback/private/link-local byte tests. Invalid input is NOT classified
// local. IPv6 ULA/private ranges are not tested here; IPv4 link-local is not
// tested.
bool local_connection_address(IpContracts &r, const ByteString &value) {
  const auto parsed = r.original_parse_ip_16(value);
  if (!parsed.valid)
    return false;
  const auto &b = parsed.bytes;
  bool mapped = true;
  for (std::size_t k = 0; k < 10; ++k)
    if (b[k] != 0)
      mapped = false;
  mapped = mapped && b[10] == 255 && b[11] == 255;
  if (mapped)
    return b[12] == 127 || b[12] == 10 ||
           (b[12] == 172 && b[13] >= 16 && b[13] <= 31) ||
           (b[12] == 192 && b[13] == 168);
  bool loopback = b[15] == 1;
  for (std::size_t k = 0; k < 15; ++k)
    if (b[k] != 0)
      loopback = false;
  return loopback || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80);
}
struct ConnectionRecord {
  std::int32_t pid = 0;
  std::uint32_t local_port = 0, remote_port = 0;
  ByteString remote_ip, status;
};
// Recovered (dx5zItfyp@1c4a9e0): caller requested a TCP table. This selector
// checks the supplied rows themselves for exact state, PID, remote port and
// address. It returns only the remote IP, choosing lowest LOCAL port; first
// equal-port wins.
ByteString java_connection_candidate(IpContracts &r,
                                     const std::vector<ConnectionRecord> &rows,
                                     std::int32_t pid) {
  const ConnectionRecord *best = nullptr;
  for (const auto &row : rows) {
    if (row.pid != pid || row.status != "ESTABLISHED" ||
        row.remote_port != 25565)
      continue;
    if (row.remote_ip.empty() || row.remote_ip == "127.0.0.1" ||
        row.remote_ip == "::1")
      continue;
    if (local_connection_address(r, row.remote_ip))
      continue;
    if (best == nullptr || row.local_port < best->local_port)
      best = &row;
  }
  return best ? best->remote_ip : ByteString{};
}
struct DnsRecordPrefix {
  std::uint64_t original_address = 0, next = 0;
  std::uint16_t type = 0, data_length = 0;
  std::array<std::uint8_t, 4> a_address{};
};
struct DnsMatchContracts {
  struct Defers {
    virtual ~Defers() = default;
    virtual void add(const std::function<void()> &) = 0;
  };
  struct QueryResult {
    std::uint64_t status = 0, records = 0;
  };
  virtual ~DnsMatchContracts() = default;
  virtual bool
  original_go_defer_scope(const std::function<bool(Defers &)> &) = 0;
  virtual Result<std::uint64_t>
  original_utf16_pointer_from_string(const ByteString &) = 0;
  virtual QueryResult original_dns_query_w(std::uint64_t name,
                                           std::uint16_t type,
                                           std::uint32_t options,
                                           std::uint64_t reserved1,
                                           std::uint64_t reserved2) = 0;
  virtual DnsRecordPrefix read_original_dns_record_prefix(std::uint64_t) = 0;
  virtual void original_dns_record_list_free(std::uint64_t) = 0;
};
// Recovered (fyRro7@1c4bf20): caller GL_Ufx supplies a normalized four-byte
// IPv4 target. DnsQuery_W uses type A=1, options0x10 (DNS_QUERY_NO_WIRE_QUERY:
// cache only), both reserved pointers NULL. No query implementation is supplied
// in this source. Original query-status failure returns before installing the
// record-free defer.
bool cached_dns_matches_ipv4(DnsMatchContracts &r, const ByteString &domain,
                             const std::array<std::uint8_t, 4> &target) {
  return r.original_go_defer_scope([&](DnsMatchContracts::Defers &defers) {
    const auto name = r.original_utf16_pointer_from_string(domain);
    if (name.error.present())
      return false;
    const auto query = r.original_dns_query_w(name.value, 1, 0x10, 0, 0);
    if (query.status != 0)
      return false;
    if (query.records != 0)
      defers.add(
          [&r, p = query.records] { r.original_dns_record_list_free(p); });
    auto p = query.records;
    for (std::uint32_t k = 0; p != 0 && k < 256; ++k) {
      const auto row = r.read_original_dns_record_prefix(p);
      if (row.type == 1 && row.data_length >= 4 && row.a_address == target)
        return true;
      p = row.next;
    }
    return false;
  });
}
// Evidence: 16 original IP-classifier fixtures; 14 selector fixtures (locality
// explicitly modeled in those fixtures); nine original cached-DNS match
// fixtures. ParseIP, native cache-table enumeration and full GL_Ufx
// selection/error text remain explicit dependencies. Source not compiled or
// executed. DNS flag reference:
// https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants
} // namespace ocean::reconstructed::minecraft_review
