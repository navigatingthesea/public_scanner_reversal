#include "java_agent_inputs.hpp"
namespace ocean::reconstructed::minecraft_agent_input_review {
// Purpose: find processes whose names or command lines make them relevant to
// Java-agent checks, then collect the startup text consumed by those checks.
// Recovered (hZYi8ltydAg@1c3ed20): reads this scanner process's environment via
// os.Getenv; it does not fetch a separate environment block from each Java PID.
// One row per matching variable; full original value is included, not just
// an extracted agent filename. Substring tests do not require ':' or a
// boundary.
void collect_java_agent_environment(AgentInputContracts &r) {
  for (const auto name : {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
                          "JDK_JAVA_OPTIONS", "JAVA_OPTS"}) {
    const auto value = r.original_getenv(name);
    if (value.empty())
      continue;
    const auto lower = r.to_lower(value);
    if (lower.find("-javaagent") != ByteString::npos ||
        lower.find("-agentlib") != ByteString::npos ||
        lower.find("-agentpath") != ByteString::npos)
      r.append_debug_row({"Warning", "JVMEnvAgent", name, value});
  }
}
// Recovered (s0Iqq6sONpkY@1c36280): applies to all enumerated processes. Exact
// lowercase name java.exe/javaw.exe accepts an arbitrary nonempty command line.
// If the name query fails or does not match, four command-line substrings are
// an alternative. -agentlib alone and lunar.genesis alone are not alternatives.
bool is_java_agent_check_candidate(AgentInputContracts &r,
                                   AgentProcessRef process,
                                   const ByteString &command) {
  const auto name = r.original_process_name(process);
  if (!name.error.present()) {
    const auto lower = r.to_lower(name.value);
    if (lower == "java.exe" || lower == "javaw.exe")
      return true;
  }
  const auto lower = r.to_lower(command);
  return lower.find("-javaagent:") != ByteString::npos ||
         lower.find("-agentpath:") != ByteString::npos ||
         lower.find("-xbootclasspath") != ByteString::npos ||
         lower.find("net.minecraft.client") != ByteString::npos;
}
// Recovered (eEvOCTP@1c37f60 / func1@1c38180): enumerates all processes and
// launches one job per process, with semaphore capacity 8 and WaitGroup
// completion. A nil error and nonempty Cmdline is required before candidate
// filtering. Name is queried again for the output record; that second error is
// ignored. Records append under the original mutex; worker completion order
// varies.
std::vector<AgentProcessRecord>
collect_java_agent_process_records(AgentInputContracts &r) {
  const auto processes = r.original_enumerate_all_processes();
  if (processes.error.present())
    return {};
  r.original_run_process_jobs_with_semaphore_and_waitgroup(
      processes.value, 8, [&](AgentProcessRef process) {
        const auto command = r.original_process_command_line(process);
        if (command.error.present() || command.value.empty())
          return;
        if (!is_java_agent_check_candidate(r, process, command.value))
          return;
        const auto name = r.original_process_name(process);
        r.original_append_process_record_under_mutex(
            {static_cast<GoInt>(process.pid), name.value, command.value});
      });
  return r.original_completed_process_records();
}
// e3j0Txkl_DS@1c33f20. Generic parser; each caller supplies its exact
// needle (the agent checks use '-javaagent:', '-agentpath:', '-agentlib:').
// Searches a lowercased COPY but slices the original bytes. A match must be
// at start or preceded by space/tab/double quote. Value extends until end or
// space/tab immediately followed by '-'. Quotes do not protect that boundary.
// This intentionally retains its handling of spaces and quoted hyphens.
StringList extract_option_values(AgentInputContracts &r,
                                 const ByteString &command,
                                 const ByteString &needle) {
  StringList result;
  if (command.empty() || needle.empty())
    return result;
  const auto lower_command = r.to_lower(command),
             lower_needle = r.to_lower(needle);
  std::size_t offset = 0;
  while (true) {
    r.original_bounds_check(offset, lower_command.size());
    const auto at = lower_command.find(lower_needle, offset);
    if (at == ByteString::npos)
      break;
    const auto value_start = at + lower_needle.size();
    if (at > 0) {
      r.original_bounds_check(at - 1, command.size() - 1);
      const auto preceding = command[at - 1];
      if (preceding != ' ' && preceding != '\t' && preceding != '"') {
        offset = value_start;
        continue;
      }
    }
    r.original_bounds_check(value_start, command.size());
    auto end = command.size();
    for (std::size_t i = value_start; i + 1 < command.size(); ++i)
      if ((command[i] == ' ' || command[i] == '\t') && command[i + 1] == '-') {
        end = i;
        break;
      }
    const auto value = r.original_trim_right(
        r.original_trim_left(command.substr(value_start, end - value_start),
                             " \""),
        " \t\"");
    if (!value.empty()) {
      result.has_backing_storage = true;
      result.items.push_back(value);
    }
    if (end < 1)
      break;
    offset = end;
  }
  return result;
}
// Z_1Z44g@1c40780 / controller worker27@1f009e0. Environment collection
// precedes all-process selection, then four checks run for each nonempty
// cmdline. The four argument-check bodies are reviewed in
// java_agent_checks.cpp. This dispatcher retains the original
// helper-binding/runtime contract.
void run_minecraft_java_agent_checks(AgentInputContracts &r) {
  r.original_timed_recovery_scope([&] {
    collect_java_agent_environment(r);
    for (const auto &process : collect_java_agent_process_records(r))
      if (!process.command_line.empty()) {
        r.original_agent_file_checks(process);
        r.original_debug_bootclasspath_checks(process);
        r.original_dynamic_attach_checks(process);
        r.original_classpath_checks(process);
      }
  });
}
// Evidence: nine environment fixtures, 14 candidate-selector fixtures, 13
// generic parser fixtures, and static semaphore/mutex/body reads. All providers
// are explicit contracts; four argument-check cores are separately
// reconstructed. Environment result 572e8e0 merges 572e700, goes through
// Ovn8CoJsB, then feeds DEBUG_DETECTIONS at 1f06639. That transform is reviewed
// separately; do not assume its behavior equals HCZ3Ed's string-list
// normalization. Review text only; never compiled or executed.
} // namespace ocean::reconstructed::minecraft_agent_input_review
