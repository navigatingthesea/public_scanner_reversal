#pragma once
#include "../../session/session_types.hpp"
#include <array>
namespace ocean::reconstructed::minecraft_agent_input_review {
// Shared data and provider contracts for Java startup-option collection.
using DebugRow = std::array<ByteString, 4>;
struct AgentProcessRef {
  std::uint64_t original_pointer;
  std::int32_t pid;
};
struct AgentProcessRecord {
  GoInt pid;
  ByteString name; // executable/process name
  ByteString command_line;
}; // original40 bytes
struct AgentInputContracts : TextContracts {
  virtual ByteString
  original_getenv(const ByteString &) = 0; // scanner-process environment
  virtual Result<ByteString> original_process_name(AgentProcessRef) = 0;
  virtual Result<ByteString> original_process_command_line(AgentProcessRef) = 0;
  virtual Result<std::vector<AgentProcessRef>>
  original_enumerate_all_processes() = 0;
  virtual void original_run_process_jobs_with_semaphore_and_waitgroup(
      const std::vector<AgentProcessRef> &, std::size_t capacity,
      const std::function<void(AgentProcessRef)> &) = 0;
  virtual void
  original_append_process_record_under_mutex(const AgentProcessRecord &) = 0;
  virtual std::vector<AgentProcessRecord>
  original_completed_process_records() = 0;
  virtual ByteString original_trim_left(const ByteString &,
                                        const ByteString &cutset) = 0;
  virtual ByteString original_trim_right(const ByteString &,
                                         const ByteString &cutset) = 0;
  virtual void original_bounds_check(std::size_t position,
                                     std::size_t length) = 0;
  virtual void append_debug_row(
      const DebugRow
          &) = 0; // 572e8e0; aggregate DEBUG_DETECTIONS after Ovn8CoJsB
  virtual void original_timed_recovery_scope(const std::function<void()> &) = 0;
  virtual void
  original_agent_file_checks(const AgentProcessRecord &) = 0; // damhYtR@1c38540
  virtual void original_debug_bootclasspath_checks(
      const AgentProcessRecord &) = 0; // f1vi8AvMKsU@1c3b5c0
  virtual void original_dynamic_attach_checks(
      const AgentProcessRecord &) = 0; // aaJ5Ym5r@1c3c3a0
  virtual void
  original_classpath_checks(const AgentProcessRecord &) = 0; // tsez1VIF@1c3e6e0
};
StringList extract_option_values(AgentInputContracts &, const ByteString &,
                                 const ByteString &);
bool is_java_agent_check_candidate(AgentInputContracts &, AgentProcessRef,
                                   const ByteString &);
void collect_java_agent_environment(AgentInputContracts &);
} // namespace ocean::reconstructed::minecraft_agent_input_review
