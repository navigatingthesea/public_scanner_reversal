#include "../../session/session_types.hpp"
#include <bit>
#include <functional>
namespace ocean::reconstructed::minecraft_log_review {
// Purpose: infer the currently connected non-IP server hostname from the tail
// of <gameDir>/logs/latest.log for one Java PID. Only port 25565 connections
// are retained, and any recognized disconnect line clears the candidate.
using Buffer = std::uint64_t;
using File = std::uint64_t;
using FileInfo = std::uint64_t;
struct LogContracts : TextContracts {
  struct Defers {
    virtual ~Defers() = default;
    virtual void add(const std::function<void()> &) = 0;
  };
  struct ReadResult {
    GoInt count = 0;
    GoError error{0, 0};
  };
  virtual Result<std::uint64_t> original_process_from_pid(std::int32_t) = 0;
  virtual Result<ByteString> original_command_line(std::uint64_t process) = 0;
  virtual std::vector<ByteString>
  original_regex_find_string_submatch(const ByteString &expression,
                                      const ByteString &value) = 0;
  virtual bool original_regex_matches(const ByteString &expression,
                                      const ByteString &value) = 0;
  virtual ByteString original_windows_join(const std::vector<ByteString> &) = 0;
  virtual Result<File> original_open_readonly_file(const ByteString &) = 0;
  virtual void original_close_file(File) = 0;
  virtual Result<FileInfo> original_file_stat(File) = 0;
  virtual GoInt original_file_info_size(FileInfo) = 0;
  virtual Buffer original_make_byte_slice(
      GoInt length, GoInt capacity) = 0; // preserves original panic bounds
  virtual ReadResult original_read_at(File, Buffer, GoInt offset) = 0;
  virtual bool original_error_equals_io_eof(GoError) = 0;
  virtual ByteString
  original_byte_prefix_to_string(Buffer,
                                 GoInt count) = 0; // original bounds/panics
  virtual bool original_parse_ip_succeeds(const ByteString &) = 0;
  virtual ByteString
  original_file_defer_scope(const std::function<ByteString(Defers &)> &) = 0;
};
constexpr const char *game_dir_pattern =
    R"rx((?i)(?:^|\s)--gameDir(?:=|\s+)(?:"([^"]+)"|(\S+)))rx";
constexpr const char *connection_pattern =
    R"((?i)Connecting to\s*([^,\r\n]+)\s*,\s*(\d+))";
constexpr const char *disconnected_patterns[] = {
    R"((?i)Client disconnected with reason:\s*(.*)$)",
    R"((?i)Lost connection:\s*(.*)$)", R"((?i)Disconnected from\s+(.+)$)"};
GoInt subtract_go_int64(GoInt a, GoInt b) {
  return std::bit_cast<GoInt>(static_cast<std::uint64_t>(a) -
                              static_cast<std::uint64_t>(b));
}
// Recovered (q9cr78Skf@1c4d080): exact regex strings and `logs/latest.log`
// join. Keep the THREE separate Size calls. The original allocates the tail
// window, accepts exact io.EOF together with returned data, rejects other
// ReadAt errors, and lets the original byte-slice provider enforce
// count/allocation bounds.
ByteString server_name_from_latest_log(LogContracts &r, std::int32_t pid) {
  const auto process = r.original_process_from_pid(pid);
  if (process.error.present())
    return {};
  const auto command = r.original_command_line(process.value);
  if (command.error.present())
    return {};
  const auto args =
      r.original_regex_find_string_submatch(game_dir_pattern, command.value);
  if (args.size() != 3)
    return {};
  const auto dir = args[1].empty() ? args[2] : args[1];
  if (dir.empty())
    return {};
  const auto path = r.original_windows_join({dir, "logs", "latest.log"});
  const auto file = r.original_open_readonly_file(path);
  if (file.error.present())
    return {};
  return r.original_file_defer_scope(
      [&](LogContracts::Defers &defers) -> ByteString {
        defers.add([&r, p = file.value] { r.original_close_file(p); });
        const auto info = r.original_file_stat(file.value);
        if (info.error.present())
          return {};
        if (r.original_file_info_size(info.value) < 1)
          return {};
        const auto delta =
            subtract_go_int64(r.original_file_info_size(info.value), 8388608);
        const auto offset = delta > 0 ? delta : 0;
        const auto count =
            subtract_go_int64(r.original_file_info_size(info.value), offset);
        const auto buffer = r.original_make_byte_slice(count, count);
        const auto read = r.original_read_at(file.value, buffer, offset);
        if (read.error.present() && !r.original_error_equals_io_eof(read.error))
          return {};
        auto text = r.original_byte_prefix_to_string(buffer, read.count);
        if (offset > 0) {
          const auto newline = text.find('\n');
          if (newline != ByteString::npos)
            text = text.substr(newline + 1);
        }
        for (std::size_t k = 0; (k = text.find("\r\n", k)) != ByteString::npos;)
          text.replace(k, 2, "\n");
        ByteString current;
        std::size_t first = 0;
        while (true) {
          const auto end = text.find('\n', first);
          const auto line = text.substr(
              first, end == ByteString::npos ? ByteString::npos : end - first);
          const auto match =
              r.original_regex_find_string_submatch(connection_pattern, line);
          if (match.size() == 3) {
            // A connection on another port leaves the earlier candidate
            // unchanged.
            if (r.trim_space(match[2]) == "25565")
              current = r.trim_space(match[1]);
          } else {
            for (const auto *expression : disconnected_patterns)
              if (r.original_regex_matches(expression, line)) {
                current.clear();
                break;
              }
          }
          if (end == ByteString::npos)
            break;
          first = end + 1;
        }
        if (current.empty() || r.original_parse_ip_succeeds(current))
          return {};
        return current;
      });
}
// Evidence: captured regexp layout/global strings, original path-building
// probe, and 15 original-instruction ASCII log/error/EOF fixtures. Large-tail
// behavior is statically retained above; it is not claimed dynamically
// fixture-tested. Original regex, Unicode trim, file/Go runtime and IP parsing
// stay contracts. This source was not compiled or executed.
} // namespace ocean::reconstructed::minecraft_log_review
