#include "java_agent_inputs.hpp"
namespace ocean::reconstructed::minecraft_agent_input_review {
// Purpose: enumerate Windows named-pipe names and flag names that appear to be
// JVM attach channels. It does not open, connect to, or read from a pipe.
struct PipeFindBuffer {
  std::array<std::uint8_t, 600> bytes{};
}; // original Go type377a9e0
struct PipeCheckContracts : TextContracts {
  using Handle = std::uint64_t;
  virtual Result<std::u16string>
  original_utf16_from_string(const ByteString &) = 0;
  virtual Handle original_find_first_file_w(const std::u16string &,
                                            PipeFindBuffer &) = 0;
  virtual bool original_find_next_file_w(Handle, PipeFindBuffer &) = 0;
  virtual void original_register_deferred_find_close(Handle) = 0;
  virtual ByteString original_utf16_units_to_string(const std::uint8_t *bytes,
                                                    std::size_t unit_count) = 0;
  virtual void append_warning(const ByteString &) = 0;
  virtual void append_debug_strings(const std::vector<ByteString> &) = 0;
};
// lNiksAj@1c0ab80. Enumerates named pipes via FindFirstFileW/FindNextFileW;
// no pipe connection/open/read is attempted by this body. Close is deferred
// after a valid search handle. It has no per-PID association or maximum count.
void check_live_jvm_attach_pipe_names(PipeCheckContracts &r) {
  const auto pattern = r.original_utf16_from_string("\\\\.\\pipe\\*");
  if (pattern.error.present())
    return;
  PipeFindBuffer data;
  const auto handle = r.original_find_first_file_w(pattern.value, data);
  if (handle == 0xffffffffffffffffULL)
    return;
  r.original_register_deferred_find_close(handle);
  do {
    // Recovered layout quirk: the Go file-name field begins at offset 48,
    // while native WIN32_FIND_DATAW begins at 44. Thus the first two UTF-16
    // code units from the native file name are skipped. Do not fix this in a
    // behavior review.
    const auto name =
        r.original_utf16_units_to_string(data.bytes.data() + 48, 260);
    const auto lower = r.to_lower(name);
    if (lower.compare(0, 8, "javatool") == 0) {
      r.append_warning("Live JVM Attach Channel:::Named Pipe:::.:::JVM attach "
                       "pipe:::Pipe: \\\\.\\pipe\\" +
                       name);
      r.append_debug_strings({"Warning", "JVMAttachPipe", name});
    }
  } while (r.original_find_next_file_w(handle, data));
}
// Evidence: primitive layout/native compatibility verified by a benign
// local-only pipe fixture inside Sandbox, independent from original code.
// Native name ocean-analysis-native-layout-fixture became
// ean-analysis-native-layout-fixture in the Go view. The fixture closed both
// its own handles. Nine original core fixtures used intercepted native results;
// xxjavatool matched, javatool did not. Original native sample/collectors and
// this C++ were never executed. Docs:
// https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw
//       https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
// Full native errors, concurrent enumeration and Unicode/panic/defer behavior
// remain contracts. Review text only; never compiled or executed.
} // namespace ocean::reconstructed::minecraft_agent_input_review
