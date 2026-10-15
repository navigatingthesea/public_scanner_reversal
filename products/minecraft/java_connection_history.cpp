#include "../../session/session_types.hpp"
#include <algorithm>
#include <set>
namespace ocean::reconstructed::minecraft_connection_history {
// Purpose: recover recent Minecraft server connect/disconnect history from log
// directories that are already open by selected Java processes. This differs
// from q9cr78Skf's current-server tail lookup in java_server_log.cpp.
// Original Go, filesystem, gzip, time, and regex behavior remains contractual.
struct CalendarDay {
  GoInt year, month, day;
};
struct DirectoryEntry {
  ByteString name;
  bool is_directory;
};
struct FileInfoReview {
  std::uint64_t original_itab, original_data;
};
struct IntermediateEvent {
  TimeWords time{};
  ByteString type, host;
  GoInt port = 0;
  ByteString message, from_host;
}; // Original3768e80: 96 bytes; Time/type/host/port/message/fromHost at
   // offsets 0/24/40/56/64/80.
struct Event {
  ByteString time, type, host, message, from_host, summary;
}; // Original3768c80: 96 bytes; six strings at offsets 0/16/32/48/64/80.
struct History {
  ByteString boot_time;
  std::vector<Event> events;
};
struct HistoryContracts : TextContracts {
  virtual std::vector<GoInt> selected_java_pids() = 0; // 57321c0/c8/d0
  virtual TimeWords
  boot_override_or_host_boot_seconds() = 0; // eP6ebKN5EO@1c10880
  virtual Result<std::vector<ByteString>>
      open_file_paths(GoInt) = 0; // vJt.YBQLqHK@182a720
  virtual ByteString windows_base(const ByteString &) = 0; // 1d6bc0
  virtual ByteString windows_dir(const ByteString &) = 0;  // 1d6ce0
  virtual ByteString
  windows_join(const std::vector<ByteString> &) = 0; // 4e01c0
  virtual Result<std::vector<DirectoryEntry>>
  read_directory(const ByteString &) = 0;
  virtual Result<FileInfoReview> stat(const ByteString &) = 0;
  virtual std::vector<ByteString> regexp_submatches(const ByteString &,
                                                    const ByteString &) = 0;
  virtual bool regexp_matches(const ByteString &, const ByteString &) = 0;
  virtual Result<GoInt> atoi(const ByteString &) = 0;
  virtual CalendarDay calendar_fields(TimeWords) = 0;
  virtual TimeWords date_local(CalendarDay, GoInt hour, GoInt minute,
                               GoInt second) = 0;
  virtual Result<TimeWords> parse_date_in_local(const ByteString &layout,
                                                const ByteString &) = 0;
  virtual bool before(TimeWords, TimeWords) = 0;
  virtual bool time_equal(TimeWords, TimeWords) = 0;
  virtual ByteString format_time(TimeWords, const ByteString &) = 0;
  virtual std::vector<ByteString>
  split_lines_after_crlf_to_lf(const ByteString &) = 0;
  virtual Result<ByteString> original_bounded_log_reader(
      const ByteString &) = 0; // hY0H0awRgZ@1c121a0, see contract below
  virtual TimeWords
  original_file_base_day(const ByteString &,
                         FileInfoReview) = 0; // g8kqieWU4@1c11a80, below
  virtual void original_unstable_sort(
      std::vector<IntermediateEvent> &,
      const std::function<bool(const IntermediateEvent &,
                               const IntermediateEvent &)> &) = 0;
  virtual void original_timing_and_defer_epilogue() = 0;
};
constexpr auto timestamp_re = R"(^\[(\d{2}):(\d{2}):(\d{2})\])";
constexpr auto dated_log_re = R"(^(\d{4}-\d{2}-\d{2})-\d+\.log\.gz$)";
constexpr auto connect_re = R"((?i)Connecting to\s*([^,\r\n]+)\s*,\s*(\d+))";
constexpr auto client_disconnect_re =
    R"((?i)Client disconnected with reason:\s*(.*)$)";
constexpr auto lost_re = R"((?i)Lost connection:\s*(.*)$)";
constexpr auto from_re = R"((?i)Disconnected from\s+(.+)$)";
constexpr auto time_layout = "2006-01-02T15:04:05Z07:00";
bool nonzero(TimeWords t) { return t.word_0 != 0 || t.word_1 != 0; }

// xO4yakaU@1c10920. Input is open-file paths, not guessed installation paths.
// Base is EqualFold("latest.log"); dedup of parent strings is CASE SENSITIVE.
std::vector<ByteString> log_roots(HistoryContracts &r,
                                  const std::vector<ByteString> &paths) {
  std::set<ByteString> seen;
  std::vector<ByteString> out;
  for (const auto &path : paths) {
    if (!r.equal_fold(r.windows_base(path), "latest.log"))
      continue;
    const auto parent = r.windows_dir(path);
    if (seen.insert(parent).second)
      out.push_back(parent);
  }
  return out;
}
// fRN7xIYJUdz1@1c10c60. Include all case-insensitive .log.gz suffixes.
// Only successfully parsed dated names before cutoff's LOCAL midnight are
// discarded. Missing/malformed date or parse error keeps the gzip candidate.
// Sort retained ORIGINAL names lexicographically, append literal latest.log
// last if any EqualFold entry existed. It does not return original LATEST.LOG.
Result<std::vector<ByteString>>
log_files(HistoryContracts &r, const ByteString &root, TimeWords cutoff) {
  auto directory = r.read_directory(root);
  if (directory.error.present())
    return {{}, directory.error};
  const auto midnight = nonzero(cutoff)
                            ? r.date_local(r.calendar_fields(cutoff), 0, 0, 0)
                            : TimeWords{};
  bool latest = false;
  std::vector<ByteString> names;
  for (const auto &entry : directory.value) {
    if (entry.is_directory)
      continue;
    if (r.equal_fold(entry.name, "latest.log")) {
      latest = true;
      continue;
    }
    const auto lower = r.to_lower(entry.name);
    if (lower.size() < 7 || lower.compare(lower.size() - 7, 7, ".log.gz") != 0)
      continue;
    if (nonzero(midnight)) {
      const auto groups = r.regexp_submatches(dated_log_re, entry.name);
      if (groups.size() == 2) {
        const auto day = r.parse_date_in_local("2006-01-02", groups[1]);
        if (!day.error.present() && r.before(day.value, midnight))
          continue;
      }
    }
    names.push_back(entry.name);
  }
  std::sort(names.begin(), names.end());
  std::vector<ByteString> paths;
  for (const auto &name : names)
    paths.push_back(r.windows_join({root, name}));
  if (latest)
    paths.push_back(r.windows_join({root, "latest.log"}));
  return {paths, {}};
}
// v6XIXLF@1c12580. Anchored HH:MM:SS with exactly two ASCII digits per
// component, with all three Atoi errors tested. There are no separate 0..23 or
// 0..59 range checks: integers are passed directly to time.Date (including 99).
// Calendar fields come from file base time, while Date always uses original
// time.Local.
bool line_time(HistoryContracts &r, const ByteString &line, TimeWords base,
               TimeWords &out) {
  const auto groups = r.regexp_submatches(timestamp_re, line);
  if (groups.size() != 4)
    return false;
  const auto h = r.atoi(groups[1]), m = r.atoi(groups[2]),
             s = r.atoi(groups[3]);
  if (h.error.present() || m.error.present() || s.error.present())
    return false;
  out = r.date_local(r.calendar_fields(base), h.value, m.value, s.value);
  return true;
}
ByteString truncate_bytes_with_ellipsis(const ByteString &value,
                                        std::size_t maximum) {
  return value.size() > maximum ? value.substr(0, maximum) + "\xE2\x80\xA6"
                                : value;
}
// vbkNZ54@1c12760. CRLF->LF before splitting. Time BEFORE cutoff excluded;
// equal time kept. There is no port-25565 restriction in this history parser.
std::vector<IntermediateEvent> parse_log(HistoryContracts &r,
                                         const ByteString &bytes,
                                         TimeWords base, TimeWords cutoff) {
  const auto lines = r.split_lines_after_crlf_to_lf(bytes);
  std::vector<IntermediateEvent> out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    TimeWords time{};
    if (!line_time(r, lines[i], base, time))
      continue;
    if (nonzero(cutoff) && r.before(time, cutoff))
      continue;
    auto groups = r.regexp_submatches(connect_re, lines[i]);
    if (groups.size() == 3) {
      // Port Atoi error is ignored by this caller; original returned integer
      // used.
      const auto port = r.atoi(r.trim_space(groups[2]));
      out.push_back(
          {time, "connect", r.trim_space(groups[1]), port.value, {}, {}});
      continue;
    }
    groups = r.regexp_submatches(client_disconnect_re, lines[i]);
    if (groups.size() >= 2) {
      auto message = r.trim_space(groups[1]);
      std::vector<ByteString> continuation;
      std::size_t next = i + 1;
      for (; next < lines.size(); ++next) {
        const auto text = r.trim_space(lines[next]);
        if (!text.empty() && r.regexp_matches(timestamp_re, text))
          break;
        if (!text.empty())
          continuation.push_back(text);
      }
      if (!continuation.empty()) {
        message += " | ";
        for (std::size_t k = 0; k < continuation.size(); ++k) {
          if (k)
            message += ' ';
          message += continuation[k];
        }
      }
      // Reprocess the timestamp line in its ORIGINAL untrimmed form. Thus an
      // indented timestamp ends continuation but fails line_time afterward.
      i = next == 0 ? 0 : next - 1;
      out.push_back({time,
                     "disconnect",
                     {},
                     0,
                     truncate_bytes_with_ellipsis(r.trim_space(message), 1800),
                     {}});
      continue;
    }
    if (r.regexp_matches(lost_re, lines[i])) {
      groups = r.regexp_submatches(lost_re, lines[i]);
      if (groups.size() > 1)
        out.push_back({time,
                       "disconnect",
                       {},
                       0,
                       "lost: " + truncate_bytes_with_ellipsis(
                                      r.trim_space(groups[1]), 800),
                       {}});
    } else if (r.regexp_matches(from_re, lines[i])) {
      groups = r.regexp_submatches(from_re, lines[i]);
      if (groups.size() > 1)
        out.push_back({time,
                       "disconnect",
                       {},
                       0,
                       "from: " + truncate_bytes_with_ellipsis(
                                      r.trim_space(groups[1]), 800),
                       {}});
    }
  }
  return out;
}
// A2.func3@1c156c0: time, connect-before-other-type on time tie, host,
// signed int64 port, then message byte order. Equal records are not
// deduplicated.
bool event_less(HistoryContracts &r, const IntermediateEvent &a,
                const IntermediateEvent &b) {
  if (!r.time_equal(a.time, b.time))
    return r.before(a.time, b.time);
  if (a.type != b.type)
    return a.type == "connect";
  if (a.host != b.host)
    return a.host < b.host;
  if (a.port != b.port)
    return a.port < b.port;
  return a.message < b.message;
}
// v9tUe95@1c13920. Last connect wins; first subsequent disconnect consumes
// its host. Orphan and additional disconnects have no assigned from_host.
void pair_disconnects(std::vector<IntermediateEvent> &events) {
  ByteString active_host;
  bool connected = false;
  for (auto &e : events) {
    if (e.type == "connect") {
      active_host = e.host;
      connected = true;
    } else if (e.type == "disconnect") {
      if (connected)
        e.from_host = active_host;
      connected = false;
    }
  }
}
// e8FCs5jo@1c13bc0. The final event schema drops the port for every event.
std::vector<Event> final_events(HistoryContracts &r,
                                const std::vector<IntermediateEvent> &input) {
  std::vector<Event> out;
  for (const auto &e : input) {
    Event row{r.format_time(e.time, time_layout), e.type, {}, {}, {}, {}};
    if (e.type == "connect")
      row.host = e.host;
    else if (e.type == "disconnect") {
      row.message = e.message;
      row.from_host = e.from_host;
      if (!e.from_host.empty())
        row.summary = "Disconnected from " + e.from_host + " | " + e.message;
    }
    out.push_back(row);
  }
  return out;
}
// Provider boundary (hY0H0awRgZ): OpenFile(path, 0, 0), defer close,
// case-insensitive .gz
// selects gzip.Reader.Reset/deferClose. Both gzip and plain input wrapped in
// io.LimitReader with signed limit 0x3000000 (48 MiB), then io.ReadAll. Error
// results flow back unchanged. Runtime gzip, file I/O and defer mechanics are
// explicit standard-library provider boundaries. g8kqieWU4 contract:
// Base(path), dated filename capture/ParseInLocation first; if success use
// parsed local date. Otherwise FileInfo.ModTime.In(Local)'s day; if no FileInfo
// use Now.In(Local)'s day. Return Date(day, 00:00:00, Local).
// A2IxgAT2@1c14f60:
// per selected PID, query open files; parent roots exact dedup ACROSS all PIDs;
// directory/read/stat errors and empty content skipped.
History collect_history(HistoryContracts &r) {
  History result;
  const auto cutoff = r.boot_override_or_host_boot_seconds();
  if (nonzero(cutoff))
    result.boot_time = r.format_time(cutoff, time_layout);
  std::set<ByteString> visited_roots;
  std::vector<IntermediateEvent> events;
  for (const auto pid : r.selected_java_pids()) {
    const auto paths = r.open_file_paths(pid);
    if (paths.error.present())
      continue;
    for (const auto &root : log_roots(r, paths.value)) {
      if (!visited_roots.insert(root).second)
        continue;
      const auto files = log_files(r, root, cutoff);
      if (files.error.present())
        continue;
      for (const auto &file : files.value) {
        const auto info = r.stat(file);
        if (info.error.present())
          continue;
        const auto text = r.original_bounded_log_reader(file);
        if (text.error.present() || text.value.empty())
          continue;
        const auto base = r.original_file_base_day(file, info.value);
        const auto parsed = parse_log(r, text.value, base, cutoff);
        events.insert(events.end(), parsed.begin(), parsed.end());
      }
    }
  }
  r.original_unstable_sort(events, [&](const auto &a, const auto &b) {
    return event_less(r, a, b);
  });
  pair_disconnects(events);
  result.events = final_events(r, events);
  r.original_timing_and_defer_epilogue();
  return result;
}
} // namespace ocean::reconstructed::minecraft_connection_history
