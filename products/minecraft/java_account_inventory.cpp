#include "../../session/session_types.hpp"
#include <memory>
#include <set>
#include <variant>
namespace ocean::reconstructed::minecraft_review {
// Purpose: collect candidate Minecraft Java account names from live JVM
// command lines, six launcher account files, and Essential installation data.
// The collector returns names only; it does not recover passwords or tokens.
// Logical review representation of exactly the JSON object/array/string cases
// accepted by e7wV_Fx. Original parser/Go interface behavior stays a contract.
struct JsonValue {
  using Object = std::vector<std::pair<ByteString, JsonValue>>;
  using Array = std::vector<JsonValue>;
  std::variant<std::monostate, ByteString, Object, Array> value;
};
using NameSet = std::set<ByteString>;
struct AccountContracts : TextContracts {
  virtual GoError original_stat_error(
      const ByteString &path) = 0; // os.Q7hADvKJS@204760; FileInfo ignored here
  virtual Result<ByteString>
  read_entire_file(const ByteString &path) = 0; // os.MzVheaG_UJ@1fd2e0
  virtual Result<JsonValue> original_json_unmarshal_any(
      const ByteString &bytes) = 0; // ylCGcV_x.VfjFEiGL0Q
  virtual ByteString original_windows_join(const std::vector<ByteString> &) = 0;
};
// Recovered (BFgM3L.jN6qKjVdgN@1b11340): check a trimmed copy. Keep the
// original untrimmed value when it passes. Length is UTF-8 bytes, not Unicode
// characters.
bool acceptable_account_name(AccountContracts &r, const ByteString &value) {
  const auto trimmed = r.trim_space(value);
  return !trimmed.empty() && trimmed.size() <= 16 &&
         trimmed.find(' ') == ByteString::npos;
}
// Recovered (BFgM3L.init@1b10340): the accepted JSON keys are:
// user, name, userid, username, and displayname. The initializer stores them
// in global5729230.
// recovered under original initializer instructions, including decoder helpers.
bool accepted_account_key(const ByteString &lower_key) {
  return lower_key == "user" || lower_key == "name" || lower_key == "userid" ||
         lower_key == "username" || lower_key == "displayname";
}
// Recovered (BFgM3L.e7wV_Fx@1b11bc0): recursion crosses all object values and
// array elements. Matching keys must have an exact JSON string value. Other
// scalar types are ignored. Deduplicate exact original byte strings, case
// sensitively.
void collect_account_names(AccountContracts &r, const JsonValue &node,
                           NameSet &found) {
  if (const auto *object = std::get_if<JsonValue::Object>(&node.value)) {
    for (const auto &[key, value] : *object) {
      if (accepted_account_key(r.to_lower(key))) {
        if (const auto *text = std::get_if<ByteString>(&value.value))
          if (acceptable_account_name(r, *text))
            found.insert(*text);
      }
      collect_account_names(r, value, found);
    }
  } else if (const auto *array = std::get_if<JsonValue::Array>(&node.value)) {
    for (const auto &value : *array)
      collect_account_names(r, value, found);
  }
}
// BFgM3L.ABXDR7dgt@1b11e00. Read/parse errors propagate as their original
// two-word Go error, whereas no names returns a nil slice with nil error.
Result<StringList> account_names_from_json_file(AccountContracts &r,
                                                const ByteString &path) {
  const auto bytes = r.read_entire_file(path);
  if (bytes.error.present())
    return {{}, bytes.error};
  const auto parsed = r.original_json_unmarshal_any(bytes.value);
  if (parsed.error.present())
    return {{}, parsed.error};
  NameSet found;
  collect_account_names(r, parsed.value, found);
  StringList result;
  if (!found.empty()) {
    result.has_backing_storage = true;
    result.items.assign(found.begin(), found.end());
  }
  return {result, {0, 0}};
}
// BFgM3L.C8GGga6sM@1b12100. A successful read with no matching names is
// omitted. A repeated input path replaces the earlier entry in the result map.
std::map<ByteString, StringList>
account_names_from_files(AccountContracts &r,
                         const std::vector<ByteString> &paths) {
  std::map<ByteString, StringList> result;
  for (const auto &path : paths) {
    if (r.original_stat_error(path).present())
      continue;
    const auto names = account_names_from_json_file(r, path);
    if (!names.error.present() && !names.value.items.empty())
      result[path] = names.value;
  }
  return result;
}
// Recovered subsection of NOck5V3j4Av@1b12240: six explicit file paths.
// profile_component is global572b7f0; C:\Users is a captured literal. Do not
// silently substitute environment APPDATA/USERPROFILE or another drive.
std::vector<ByteString>
known_account_file_paths(AccountContracts &r,
                         const ByteString &profile_component) {
  const auto base = r.original_windows_join({"C:\\Users", profile_component});
  return {r.original_windows_join({base, "AppData", "Roaming", ".minecraft",
                                   "launcher_accounts.json"}),
          r.original_windows_join({base, "AppData", "Roaming", ".minecraft",
                                   "labymod-neo", "accounts.json"}),
          r.original_windows_join({base, "AppData", "Roaming", ".minecraft",
                                   "sklauncher", "accounts.json"}),
          r.original_windows_join({base, "AppData", "Roaming", ".minecraft",
                                   "cosmic", "accounts.json"}),
          r.original_windows_join(
              {base, "AppData", "Roaming", "PrismLauncher", "accounts.json"}),
          r.original_windows_join(
              {base, ".lunarclient", "settings", "game", "accounts.json"})};
}
struct AccountProcessRef {
  std::uint64_t original_pointer;
};
struct WalkDirectoryEntry {
  ByteString path;
  bool original_dir_entry_is_dir;
  GoError walk_error;
};
struct CompleteAccountContracts : AccountContracts {
  virtual const std::vector<GoInt> &selected_java_pids() = 0; // 57321c0/c8/d0
  virtual Result<AccountProcessRef> original_new_process(std::int32_t) = 0;
  virtual Result<std::vector<ByteString>>
      original_command_line_arguments(AccountProcessRef) = 0;
  virtual ByteString original_trim_left(const ByteString &,
                                        const ByteString &cutset) = 0; // 247000
  virtual ByteString original_trim(const ByteString &,
                                   const ByteString &cutset) = 0; // 246e60
  virtual Result<bool> original_stat_is_directory(const ByteString &) = 0;
  virtual GoError original_windows_walk_dir(
      const ByteString &,
      const std::function<GoError(const WalkDirectoryEntry &)> &) = 0; // 4e0b60
  virtual ByteString profile_component() = 0; // 572b7f0
  virtual void original_timed_recovery_scope(const std::function<void()> &) = 0;
};
// BFgM3L.EGg60bav8JLx@1b113c0. Do not turn this into conventional
// argument parsing: the inline --username=VALUE form lowercases VALUE, while
// the separate --username VALUE form preserves its case. Later entries for
// the same key overwrite earlier values. No UUID/accessToken key is selected.
StringList account_names_from_live_java_arguments(CompleteAccountContracts &r) {
  StringList names;
  for (const auto wide_pid : r.selected_java_pids()) {
    const auto process = r.original_new_process(
        static_cast<std::int32_t>(static_cast<std::uint32_t>(wide_pid)));
    if (process.error.present())
      continue;
    const auto args = r.original_command_line_arguments(process.value);
    if (args.error.present() || args.value.empty())
      continue;
    std::map<ByteString, ByteString> values;
    for (std::size_t i = 0; i < args.value.size(); ++i) {
      const auto &arg = args.value[i];
      if (arg.size() < 2 || arg[0] != '-' || arg[1] != '-')
        continue;
      // Remove all leading '-' and lowercase this entire token.
      const auto token = r.to_lower(r.original_trim_left(arg, "-"));
      const auto equals = token.find('=');
      if (equals == ByteString::npos) {
        if (i + 1 == args.value.size())
          continue;
        const auto &next = args.value[i + 1];
        if (!next.empty() && next[0] == '-')
          continue;
        values[token] = r.original_trim(next, "\"' ");
      } else {
        // SplitN(...,2), retaining any later '=' in the value. Leading '-' in
        // this inline value is allowed; the separate-value branch rejects it.
        values[token.substr(0, equals)] =
            r.original_trim(token.substr(equals + 1), "\"' ");
      }
    }
    const auto found = values.find("username");
    if (found != values.end() && acceptable_account_name(r, found->second)) {
      names.has_backing_storage = true;
      names.items.push_back(found->second);
    }
  }
  return names; // per-PID slice; no dedup or sorting in this helper
}
// NOck5V3j4Av.func20@1b159a0 is a WalkDir callback. Only directories
// with nil walk error are examined. It checks <visited>/essential/
// microsoft_accounts.json, then applies exactly the same recursive JSON
// parser/validator as the six explicit paths. All callback cases return nil
// error, including missing files, parse failures and failed directory entries.
GoError collect_installation_directory(CompleteAccountContracts &r,
                                       const WalkDirectoryEntry &entry,
                                       NameSet &names) {
  if (entry.walk_error.present() || !entry.original_dir_entry_is_dir)
    return {0, 0};
  const auto file = r.original_windows_join(
      {entry.path, "essential", "microsoft_accounts.json"});
  if (r.original_stat_error(file).present())
    return {0, 0};
  const auto found = account_names_from_json_file(r, file);
  if (!found.error.present())
    for (const auto &value : found.value.items)
      if (acceptable_account_name(r, value))
        names.insert(value);
  return {0, 0};
}
// BFgM3L.NOck5V3j4Av@1b12240. Root merges live argv, six known account
// files, then recursively walks <profile>/AppData/Roaming/.minecraft/
// installations if the root's Stat succeeds and reports a directory. Exact
// original bytes are deduped case sensitively and sorted lexicographically.
StringList collect_minecraft_java_account_names(CompleteAccountContracts &r) {
  StringList result;
  r.original_timed_recovery_scope([&] {
    NameSet names;
    const auto live = account_names_from_live_java_arguments(r);
    for (const auto &value : live.items)
      if (acceptable_account_name(r, value))
        names.insert(value);
    const auto files = account_names_from_files(
        r, known_account_file_paths(r, r.profile_component()));
    for (const auto &[path, list] : files)
      for (const auto &value : list.items)
        if (acceptable_account_name(r, value))
          names.insert(value);
    const auto installations =
        r.original_windows_join({"C:\\Users", r.profile_component(), "AppData",
                                 "Roaming", ".minecraft", "installations"});
    const auto directory = r.original_stat_is_directory(installations);
    if (!directory.error.present() && directory.value)
      r.original_windows_walk_dir(
          installations, [&](const WalkDirectoryEntry &entry) {
            return collect_installation_directory(r, entry, names);
          }); // returned walk error is ignored by the original root
    result.has_backing_storage =
        true; // root uses make([]string,0,len(map)), including empty
    result.items.assign(names.begin(), names.end());
  });
  return result;
}
// Evidence: exact initializer whitelist, five JSON-filter instruction
// fixtures, 14 argv fixtures, a root path-join boundary trace, four WalkDir
// callback branches, and static merge/callback/sort body reads. These are
// explicit modeled-provider proofs, not claims about all OS/Unicode/runtime/Go
// panic internals. Original directory traversal semantics remain a contract.
// Review text only; never compiled or executed.
} // namespace ocean::reconstructed::minecraft_review
