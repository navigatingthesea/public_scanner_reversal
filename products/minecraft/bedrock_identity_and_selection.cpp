#include "../../session/session_types.hpp"
#include <functional>
namespace ocean::reconstructed::minecraft_review {
// Purpose: identify Bedrock/UWP Minecraft processes and read the Xbox Live
// gamertag used as the Bedrock account identity.
struct OpenFileRecord {
  ByteString path;
  std::uint64_t descriptor = 0;
};
struct ProcessObject {
  std::uint64_t original_pointer = 0;
  std::int32_t pid = 0;
};
struct BedrockContracts : TextContracts {
  using Key = std::uint64_t;
  struct Defers {
    virtual ~Defers() = default;
    virtual void add(const std::function<void()> &) = 0;
  };
  virtual Result<std::vector<std::int32_t>> original_pid_list() = 0;
  virtual Result<ProcessObject> original_process_from_pid(std::int32_t) = 0;
  virtual Result<ByteString> original_command_line(ProcessObject) = 0;
  virtual Result<std::vector<OpenFileRecord>>
      original_open_files(ProcessObject) = 0;
  // Preserve the outer original recovery helper and Go named-result/defer
  // handling; their underlying recovery implementation is a separate
  // dependency.
  virtual void original_selection_scope(std::vector<std::int64_t> &named_result,
                                        const std::function<void()> &) = 0;
  virtual void
  original_gamertag_scope(StringList &named_result,
                          const std::function<void(Defers &)> &) = 0;
  virtual Result<Key> original_open_registry_key(std::uint64_t root,
                                                 const ByteString &path,
                                                 std::uint32_t access) = 0;
  virtual Result<ByteString>
  original_registry_string(Key, const ByteString &value_name) = 0;
  virtual void original_close_registry_key(Key) = 0;
};
// Recovered (B2250_.NBOLdYn@113a800): enumerate all PIDs. The command line is
// lowercased; open-file paths are compared in their original case. Add once per
// process because the first file match ends the inner loop. No extra PID
// dedup/filter.
std::vector<std::int64_t> select_bedrock_processes(BedrockContracts &r) {
  std::vector<std::int64_t> selected;
  r.original_selection_scope(selected, [&] {
    const auto all = r.original_pid_list();
    if (all.error.present())
      return;
    for (const auto pid : all.value) {
      const auto process = r.original_process_from_pid(pid);
      if (process.error.present())
        continue;
      const auto command = r.original_command_line(process.value);
      if (command.error.present())
        continue;
      if (r.to_lower(command.value).find("minecraft") == ByteString::npos)
        continue;
      const auto files = r.original_open_files(process.value);
      if (files.error.present())
        continue;
      for (const auto &file : files.value)
        if (file.path.find("MinecraftUWP") != ByteString::npos) {
          selected.push_back(static_cast<std::int64_t>(process.value.pid));
          break;
        }
    }
  });
  return selected;
}
// Recovered (B2250_.EJSi5O@113a400): HKCU, KEY_QUERY_VALUE=1. A successfully
// read empty string is still a one-element slice. Read/open failures leave the
// result nil.
StringList read_bedrock_gamertag(BedrockContracts &r) {
  StringList result;
  r.original_gamertag_scope(result, [&](BedrockContracts::Defers &defers) {
    const auto key = r.original_open_registry_key(
        0x80000001ULL, "SOFTWARE\\Microsoft\\XboxLive", 1);
    if (key.error.present())
      return;
    defers.add([&r, key = key.value] { r.original_close_registry_key(key); });
    const auto value =
        r.original_registry_string(key.value, "UniqueModernGamertag");
    if (value.error.present())
      return;
    result.has_backing_storage = true;
    result.items = {value.value};
  });
  return result;
}
// Evidence: bedrock-process-selection-review.json (nine original-instruction
// fixtures) and post-pin/shared prefix registry literal reports. Registry type
// checking occurs in the original GetStringValue provider, kept as a contract.
// Review text only; no Windows implementation, compilation or execution.
} // namespace ocean::reconstructed::minecraft_review
