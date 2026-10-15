#include "../../../common/review_contracts.hpp"
namespace ocean::reconstructed::minecraft_log_cutoff_review {
// Purpose: choose the lower time bound for Java connection-log history. A
// shared override wins; otherwise the host boot timestamp is converted into
// the recovered Go time.Time representation.
struct HostBootInfo {
  GoUint boot_seconds;
};
struct LogCutoffContracts {
  virtual ~LogCutoffContracts() = default;
  virtual TimeWords shared_boot_override() = 0; // 572e0c0/c8/d0
  virtual Result<HostBootInfo>
  original_host_info() = 0; // Q7oH0ksl.Q6RKhzVIvfGt, uint64 at offset 24
  virtual std::uint64_t original_local_timezone_pointer() = 0;
};
// eP6ebKN5EO@1c10880. Cached wall/ext both zero means absent, regardless
// of location pointer. Nonzero cached time is returned verbatim. Otherwise,
// query host BootTime: an error or zero seconds returns zero time.Time.
TimeWords java_connection_log_boot_cutoff(LogCutoffContracts &r) {
  const auto cached = r.shared_boot_override();
  if (cached.word_0 != 0 || cached.word_1 != 0)
    return cached;
  const auto host = r.original_host_info();
  if (host.error.present() || host.value.boot_seconds == 0)
    return {0, 0, 0};
  return {0, host.value.boot_seconds + 0xe7791f700ULL,
          r.original_local_timezone_pointer()};
}
// A2IxgAT2@1c14f60 formats the nonzero cutoff and collects connection-log
// events. Its typed 40-byte result has a JSON boot_time,omitempty string at
// offset 0 and an events slice at 16. This helper uses the boot override, not
// Java's oldest-process time at 5732210/18/20. Full event/path/time filtering
// is reviewed separately. Evidence: seven cutoff fixtures plus uint64
// machine-load/caller reads.
// No original host/clock/process/native queries or C++ execution occurred.
// Review text only; never compiled or executed.
} // namespace ocean::reconstructed::minecraft_log_cutoff_review
