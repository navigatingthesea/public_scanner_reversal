#include "../../session/session_types.hpp"
namespace ocean::reconstructed::minecraft_process_time_review {
// Purpose: report a formatted age for every selected Java PID and retain the
// oldest successful process-creation timestamp for later shared checks.
struct ProcessTimeRef {
  std::uint64_t original_pointer;
};
struct JavaProcessTime {
  ByteString joined_age;
  TimeWords oldest_creation;
};
struct ProcessTimeContracts {
  virtual ~ProcessTimeContracts() = default;
  virtual const std::vector<GoInt> &selected_java_pids() = 0;
  virtual Result<ProcessTimeRef> original_new_process(std::int32_t) = 0;
  virtual Result<GoInt> original_creation_time_milliseconds(ProcessTimeRef) = 0;
  virtual std::uint64_t original_local_timezone_pointer() = 0;
  virtual GoInt original_time_since_nanoseconds(TimeWords) = 0;
  virtual ByteString
      original_age_text_formatter(GoInt) = 0; // common formatter below
  virtual bool original_time_before(TimeWords, TimeWords) = 0;
  virtual ByteString original_string_join(const std::vector<ByteString> &,
                                          const ByteString &) = 0;
  virtual void original_timed_recovery_scope(const std::function<void()> &) = 0;
};
// Recovered (WVSg94v@1c15b80): returns a string plus Go time.Time, totaling
// five words. The last3words at5732210/18/20 are wall/ext/location, not a slice
// header. Process/creation errors leave EMPTY slots. Empty formatter results
// become "not running", but successful creation time still updates the oldest
// time.
JavaProcessTime collect_java_process_time(ProcessTimeContracts &r) {
  JavaProcessTime output{};
  r.original_timed_recovery_scope([&] {
    const auto &pids = r.selected_java_pids();
    if (pids.empty()) {
      output.joined_age = "not running";
      return;
    }
    std::vector<ByteString> per_pid(pids.size());
    for (std::size_t i = 0; i < pids.size(); ++i) {
      const auto process = r.original_new_process(
          static_cast<std::int32_t>(static_cast<std::uint32_t>(pids[i])));
      if (process.error.present())
        continue;
      const auto millis = r.original_creation_time_milliseconds(process.value);
      if (millis.error.present())
        continue;
      // Signed division toward zero drops the millisecond remainder, including
      // -1500ms -> -1sec. Exact recovered non-monotonic Go time representation.
      const GoInt seconds = millis.value / 1000;
      const TimeWords created = {0,
                                 static_cast<GoUint>(seconds) + 0xe7791f700ULL,
                                 r.original_local_timezone_pointer()};
      per_pid[i] = r.original_age_text_formatter(
          r.original_time_since_nanoseconds(created));
      if (per_pid[i].empty())
        per_pid[i] = "not running";
      if (output.oldest_creation.word_1 == 0 ||
          r.original_time_before(created, output.oldest_creation))
        output.oldest_creation = created;
    }
    output.joined_age = r.original_string_join(per_pid, " | ");
  });
  return output;
}
// Controller worker29 publishes joined_age at572b990/998 (GAME_TIME) and
// oldest_creation at5732210/18/20. Later shared checks reference it.
// Java log helper eP6ebKN5EO instead reads boot override572e0c0/c8/d0;
// the two timestamps must not be conflated. No PID dedup, zero-PID skip or
// removal of error slots here. Evidence: eight core fixtures under explicit
// process/time/formatter providers, return-register proof and static caller
// stores. Real process creation queries, timer/recovery/GC and every Go time
// edge remain contracts. Review text only; never compiled or executed.
} // namespace ocean::reconstructed::minecraft_process_time_review
