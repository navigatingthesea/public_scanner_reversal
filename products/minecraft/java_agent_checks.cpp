#include "java_agent_inputs.hpp"
namespace ocean::reconstructed::minecraft_agent_input_review {
// Purpose: classify Java command-line options that enable agents, debugging,
// dynamic attachment, boot-classpath changes, or classpath entries in staging
// locations. These are text checks; they do not prove that referenced code was
// loaded or executed.
struct AgentMatchTables {
  std::vector<ByteString> path_exclusions;            // global56635d0
  std::vector<ByteString> temporary_allowed_suffixes; // 56635f0
  std::vector<ByteString> staging_substrings;         // 5663610
};
struct AgentCheckContracts : AgentInputContracts {
  virtual const AgentMatchTables &original_current_match_tables() = 0;
  virtual void append_warning(const ByteString &) = 0; // 572e7a0 -> WARNINGS
  virtual void append_variable_length_debug_row(
      const std::vector<ByteString>
          &) = 0; // 572e8e0 -> DEBUG_DETECTIONS after Ovn8CoJsB
};
// Exact captured table defaults; table reads remain a contract to preserve any
// runtime changes. No assertion that all possible PINs keep these defaults.
AgentMatchTables captured_agent_match_table_defaults() {
  return {{".lunarclient", "lunarclient", "badlion", "\\feather", ".feather",
           "\\program files\\", "\\program files (x86)\\", "\\jetbrains\\",
           "idea_rt.jar", "\\jre\\lib\\", "\\jdk\\lib\\"},
          {"\\theseus.jar"},
          {"\\downloads\\", "\\desktop\\", "$recycle.bin",
           "\\appdata\\local\\temp\\", "\\windows\\temp\\"}};
}
// jXepuiIb_@1c345e0. Input is lowercased by its callers. No Windows path
// normalization, stat, hash, JAR read or file-existence test happens here.
bool has_staging_path_substring(AgentCheckContracts &r,
                                const ByteString &lower) {
  for (const auto &needle :
       r.original_current_match_tables().staging_substrings)
    if (lower.find(needle) != ByteString::npos)
      return true;
  return false;
}
// qsJsGkF8t@1c342c0. Temp path plus LastIndex of an accepted suffix;
// suffix must end at end-of-string or be immediately followed by '='.
// The actual LastIndex body@243de0 was admitted in the original fixtures.
bool is_allowed_temporary_agent_suffix(AgentCheckContracts &r,
                                       const ByteString &lower) {
  if (lower.find("\\appdata\\local\\temp\\") == ByteString::npos &&
      lower.find("\\windows\\temp\\") == ByteString::npos)
    return false;
  for (const auto &suffix :
       r.original_current_match_tables().temporary_allowed_suffixes) {
    const auto at = lower.rfind(suffix);
    if (at == ByteString::npos)
      continue;
    const auto end = at + suffix.size();
    if (end == lower.size() || lower[end] == '=')
      return true;
  }
  return false;
}
// mjnhAM8@1c34520: temporary-suffix exception first, then 11 substring
// exclusions.
bool is_excluded_agent_path(AgentCheckContracts &r, const ByteString &lower) {
  if (is_allowed_temporary_agent_suffix(r, lower))
    return true;
  for (const auto &needle : r.original_current_match_tables().path_exclusions)
    if (lower.find(needle) != ByteString::npos)
      return true;
  return false;
}
void warning_with_debug_detail(AgentCheckContracts &r,
                               const ByteString &warning,
                               const ByteString &label,
                               const ByteString &detail) {
  r.append_warning(warning);
  r.append_variable_length_debug_row({"Warning", label, detail});
}
// damhYtR@1c38540. This body checks argument TEXT; it does not verify an
// agent actually exists, loads, injects, or belongs to Minecraft. Its warning
// text still says "Loaded Into Minecraft" for every candidate from all-process
// enumeration. The exact precedence is weave -> jdwp -> exclusion -> staging.
void check_java_agent_arguments(AgentCheckContracts &r,
                                const AgentProcessRecord &process) {
  const std::array<std::pair<const char *, const char *>, 3> options = {
      {{"-javaagent:", "Java Agent"},
       {"-agentpath:", "Java Agent"},
       {"-agentlib:", "Extra Code File"}}};
  for (const auto &[needle, kind] : options) {
    for (const auto &value :
         extract_option_values(r, process.command_line, needle).items) {
      const auto lower = r.to_lower(value);
      if (lower.find("weave") != ByteString::npos) {
        warning_with_debug_detail(
            r,
            "Weave Cheat Loader:::Java Agent:::.:::Agent argument:::Agent: " +
                value,
            "WeaveAgent", value);
      } else if (lower.find("jdwp") != ByteString::npos) {
        warning_with_debug_detail(
            r,
            "Remote Debugging:::Java Agent:::.:::Agent argument:::Agent: " +
                value,
            "JVMRemoteDebug", value);
      } else if (!is_excluded_agent_path(r, lower)) {
        const bool staging = has_staging_path_substring(r, lower);
        const auto warning =
            ByteString("Unknown ") + kind +
            ":::" + (staging ? "Staging Location" : "Loaded Into Minecraft") +
            ":::.:::Path: " + value;
        warning_with_debug_detail(
            r, warning, staging ? "JVMSuspiciousAgent" : "JVMUnknownAgent",
            value);
      }
    }
  }
}
// f1vi8AvMKsU@1c3b5c0. Either debug substring adds ONE warning/row per
// process. Every parsed bootclasspath value is recorded, including semicolon
// lists as a SINGLE unmodified value; no split, file read or allowlist here.
void check_java_debug_and_bootclasspath(AgentCheckContracts &r,
                                        const AgentProcessRecord &process) {
  const auto lower = r.to_lower(process.command_line);
  if (lower.find("-xrunjdwp") != ByteString::npos ||
      lower.find("-xdebug") != ByteString::npos) {
    r.append_warning("Remote Debugging:::Java Flags:::.:::Debug flags:::Flags: "
                     "-XrunJDWP / -Xdebug enabled");
    r.append_variable_length_debug_row({"Warning", "JVMXDebug"});
  }
  for (const auto needle : {"-Xbootclasspath/a:", "-Xbootclasspath/p:"})
    for (const auto &value :
         extract_option_values(r, process.command_line, needle).items)
      warning_with_debug_detail(r,
                                "Boot Classpath Modification:::Java "
                                "Flags:::.:::Boot classpath:::Path: " +
                                    value,
                                "JVMBootClasspath", value);
}
// aaJ5Ym5r@1c3c3a0. Three independent case-insensitive byte-substring
// checks. No word/argument boundary, PID, filename or command line is included
// in these constant output rows. Multiple JVMs can generate identical rows.
void check_java_dynamic_attach_flags(AgentCheckContracts &r,
                                     const AgentProcessRecord &process) {
  const auto lower = r.to_lower(process.command_line);
  struct Check {
    const char *needle;
    const char *warning;
    const char *debug_label;
  };
  constexpr std::array<Check, 3> checks = {
      {{"-xx:-disableattachmechanism",
        "Attach Mechanism Enabled:::Injection Prerequisites:::.:::JVM "
        "flag:::Flag: -XX:-DisableAttachMechanism",
        "JVMAttachEnabled"},
       {"-djdk.attach.allowattachself=true",
        "Self Attach Allowed:::Injection Prerequisites:::.:::JVM flag:::Flag: "
        "-Djdk.attach.allowAttachSelf=true",
        "JVMAttachSelf"},
       {"-xx:+enabledynamicagentloading",
        "Dynamic Agent Loading:::Injection Prerequisites:::.:::JVM "
        "flag:::Flag: -XX:+EnableDynamicAgentLoading",
        "JVMDynamicAgent"}}};
  for (const auto &check : checks)
    if (lower.find(check.needle) != ByteString::npos) {
      r.append_warning(check.warning);
      r.append_variable_length_debug_row({"Warning", check.debug_label});
    }
}
// tsez1VIF@1c3e6e0. Merge values from -classpath FIRST, then -cp; split
// each on ';', trim each entry, lowercase only the comparison copy. A staging
// substring and no exclusion generates a warning plus ORIGINAL trimmed entry.
void check_java_classpath_locations(AgentCheckContracts &r,
                                    const AgentProcessRecord &process) {
  for (const auto needle : {"-classpath ", "-cp "}) {
    for (const auto &value :
         extract_option_values(r, process.command_line, needle).items) {
      std::size_t start = 0;
      while (start <= value.size()) {
        const auto end = value.find(';', start);
        const auto entry = r.trim_space(value.substr(
            start, end == ByteString::npos ? ByteString::npos : end - start));
        if (!entry.empty()) {
          const auto lower = r.to_lower(entry);
          if (has_staging_path_substring(r, lower) &&
              !is_excluded_agent_path(r, lower))
            warning_with_debug_detail(r,
                                      "Suspicious Classpath Entry:::Staging "
                                      "Location:::.:::Classpath:::Entry: " +
                                          entry,
                                      "JVMClasspath", entry);
        }
        if (end == ByteString::npos)
          break;
        start = end + 1;
      }
    }
  }
}
// Evidence: 15 agent-argument, 11 classpath, four bootclasspath, and 18
// debug/attach instruction fixtures; original parser and LastIndex instructions
// admitted with intercepted bounded string/runtime providers. Captured tables
// retained with exact addresses. No files or referenced agent DLL/JARs were
// opened; neither Java, original native collectors nor this C++ were launched.
// Unicode, runtime/GC/panic/concurrency and aggregate normalization internals
// remain separate contracts. This is reviewed collector core, not proof that
// every byte of the app or every server-delivered configuration is known.
// Review text only; never compiled or executed.
} // namespace ocean::reconstructed::minecraft_agent_input_review
