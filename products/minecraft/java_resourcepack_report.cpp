#include "../../session/session_types.hpp"
#include <functional>
namespace ocean::reconstructed::resourcepack_report_review {
// Purpose: convert detected resource-pack records into warnings, CIT debug
// rows, and a gzip-compressed JSON payload for the outer report aggregate.
struct ErrorWords {
  std::uint64_t type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct GoBytes {
  bool nil_backing = true;
  std::vector<std::uint8_t> bytes;
};
struct PackSlice {
  std::uint64_t original_pointer = 0;
  GoInt length = 0, capacity = 0;
};
struct CITSlice {
  std::uint64_t original_pointer = 0;
  GoInt length = 0, capacity = 0;
};
struct ParentStats {
  PackSlice detected;
  CITSlice cit;
};
struct ParentResult {
  const ParentStats *value = nullptr;
  ErrorWords error;
};
struct JSONResult {
  GoBytes encoded;
  ErrorWords error;
};
struct Buffer {
  std::vector<std::uint8_t> bytes;
  std::size_t offset = 0;
};
struct ReportContracts {
  virtual GoBytes
  original_timing_defer_scope(const ByteString &label,
                              const std::function<GoBytes()> &) = 0;
  virtual ParentResult original_inspect_default_resourcepacks() = 0;
  [[noreturn]] virtual void original_panic_nil_parent() = 0;
  virtual void append_warning(const ByteString &) = 0;
  virtual void original_report_cit_records(
      CITSlice) = 0; // reviewed java_cit_diagnostics.cpp
  virtual JSONResult
      original_json_marshal_pack_slice(PackSlice) = 0; // type357e020
  virtual std::uint64_t original_gzip_writer_level_nine(Buffer &) = 0;
  virtual void original_gzip_write_ignoring_count_and_error(std::uint64_t,
                                                            GoBytes) = 0;
  virtual void original_gzip_close_ignoring_error(std::uint64_t) = 0;
  virtual void original_progress_or_status_log() = 0; // intercepted/out of
                                                      // scope
  [[noreturn]] virtual void original_panic_buffer_offset() = 0;
};
// Recovered (JEg1SQOq@1c5fa60): timer label X_RAY differs from aggregate key
// X-RAY.
GoBytes collect_report_bytes(ReportContracts &r) {
  return r.original_timing_defer_scope("X_RAY", [&]() -> GoBytes {
    const auto parent = r.original_inspect_default_resourcepacks();
    if (parent.error.present()) {
      r.original_progress_or_status_log();
      return {};
    }
    if (!parent.value)
      r.original_panic_nil_parent(); // not a normal reviewed parent result
    const auto &stats = *parent.value;
    if (stats.detected.length != 0) {
      const auto count = std::to_string(stats.detected.length);
      r.append_warning(count +
                       " X-RAY Texture pack(s) found:::Resource Packs "
                       "folder:::The user has " +
                       count +
                       " X-RAY Texture pack(s) in his resource packs folder");
    }
    // Warning and CIT side effects occur BEFORE JSON marshal/error handling.
    r.original_report_cit_records(stats.cit);
    const auto json = r.original_json_marshal_pack_slice(stats.detected);
    if (json.error.present()) {
      r.original_progress_or_status_log();
      return {};
    }
    Buffer buffer;
    const auto writer = r.original_gzip_writer_level_nine(buffer);
    r.original_gzip_write_ignoring_count_and_error(writer, json.encoded);
    r.original_gzip_close_ignoring_error(writer);
    if (buffer.offset > buffer.bytes.size())
      r.original_panic_buffer_offset();
    GoBytes out;
    out.nil_backing = buffer.bytes.empty();
    out.bytes.assign(buffer.bytes.begin() + buffer.offset, buffer.bytes.end());
    r.original_progress_or_status_log();
    return out;
  });
}
// Compression occurs even for an empty detected slice: normal parent initial
// slice has nonnil zerobase backing and its standard JSON representation is[]
// (encoder semantics remain explicit). Suspected/names-only/field104/root
// statistics are not fed to this marshal. Gzip write/close failures are
// ignored; any remaining bytes, including partial output, are returned under
// providers. Original buffer data-pointer/capacity/nil distinction is not
// reconstructed by the logical C++ vector above. Actual codecs,
// exception/timing/runtime and final aggregate encryption/HTTP submission
// belongs to the outer transport layer; the resource-pack collection and report
// payload are complete here.
} // namespace ocean::reconstructed::resourcepack_report_review
