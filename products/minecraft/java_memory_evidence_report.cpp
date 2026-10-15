#include "java_memory_evidence_types.hpp"
namespace ocean::reconstructed::minecraft_memory_evidence_review {
// Purpose: map the memory scanner's concrete counters to the application's
// diagnostic labels. These labels are the application's interpretation of
// heuristics; they do not independently prove injection or self-destruction.
void diagnostic(Contracts &r, const ByteString &message,
                const ByteString &label, GoInt count) {
  r.original_diagnostic_log(message);
  r.append_debug("Detect", label, count);
}
// PrintResults@1c01a40: independent branches; duplicates count individually.
// Only marked regions participate in case-sensitive label substring counts.
void report_memory_evidence(Contracts &r, const Scan &scan, GoInt pid,
                            std::size_t selected_pid_count) {
  GoInt mapped_executable_regions = 0;
  GoInt private_rwx_pe_regions = 0;
  for (const auto &region : scan.regions)
    if (region.marked) {
      if (region.label.find("mdl") != ByteString::npos)
        ++mapped_executable_regions;
      if (region.label.find("DLLMap") != ByteString::npos)
        ++private_rwx_pe_regions;
    }
  const auto suspicious_small_rwx = count_small_private_rwx(r, scan);
  if (suspicious_small_rwx > 0)
    diagnostic(r, "Cheat Injection B:::In instance", "PRWX",
               suspicious_small_rwx);
  if (private_rwx_pe_regions > 0)
    diagnostic(r, "Generic ManualMap Injection:::In instance", "DLLMAP",
               private_rwx_pe_regions);
  if (mapped_executable_regions > 2)
    diagnostic(r, "Game Process Injection [Type A]:::In instance", "MDL",
               mapped_executable_regions);
  const auto hidden_executable_allocations =
      count_inaccessible_executable_allocations(scan);
  if (hidden_executable_allocations > 0) {
    ByteString message = "Generic Internal SelfDestruct [Type C]";
    if (selected_pid_count >= 2)
      message += " [" + std::to_string(pid) + "]";
    diagnostic(r, message + ":::In instance", "FREE_REGIONS",
               hidden_executable_allocations);
  }
}
// M2IOdOwg9z4U@1c00ee0: access 0x410, inherit=false, uint32 PID. Error returns
// nil receiver with original formatter "error al abrir proceso: %v".
struct ScanResult {
  std::shared_ptr<Scan> value;
  Error error;
};
ScanResult open_scan(Contracts &r, std::uint32_t pid) {
  const auto opened = r.original_open_process(0x410, false, pid);
  if (opened.error.present())
    return {{},
            r.original_format_error_or_literal("error al abrir proceso: %v",
                                               opened.error)};
  auto scan = std::make_shared<Scan>();
  scan->handle = opened.handle;
  return {scan, {}};
}
// S9jlHuR8qjYJ@1c02600. Selected PID order/duplicates preserved. Initial
// JAR predicate is the already reconstructed process/open-file helper,
// case-sensitive substring .jar. GUI/progress/timing are omitted here.
void check_selected_java_pids(Contracts &r, const std::vector<GoInt> &pids) {
  for (const auto pid : pids) {
    if (!r.has_lowercase_jar_in_open_files(static_cast<std::int32_t>(pid)))
      continue;
    const auto opened = open_scan(r, static_cast<std::uint32_t>(pid));
    if (opened.error.present())
      continue;
    auto &scan = *opened.value;
    const auto error = collect_memory_regions(r, scan);
    if (!error.present())
      report_memory_evidence(r, scan, pid, pids.size());
    if (scan.handle)
      r.original_close_handle(
          scan.handle); // also on scan error; handle stays unchanged
  }
}
// Evidence: 12 report fixtures and 10 constructor/parent fixtures.
// Original controller skips report on scan error and still closes the handle.
// No direct WARNINGS append in these reporting bodies. Diagnostic logger
// internals, runtime panic/timing and other checks remain separate
// dependencies. No native API, sample or reconstructed C++ executed.
} // namespace ocean::reconstructed::minecraft_memory_evidence_review
