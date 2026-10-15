#include "../../common/review_contracts.hpp"
#include <vector>
#include <map>
namespace ocean::reconstructed {
// Recovered: enumerate processes with executable path and creation time, enrich
// each with admin/signature/window data, and emit newline-separated report rows
// in enumeration order. Enumeration failure returns "none"; row failures skip it.
struct ProcessReportContracts {
    struct Process {
        std::uint64_t opaque;
        std::int32_t pid;
    };
    virtual ~ProcessReportContracts() = default;
    virtual bool processes(std::vector<Process> &) = 0;             // wT5Owez4.TyWkjH @0xe53b20
    virtual std::map<std::int32_t, ByteString> window_labels() = 0; // @0xf33f00
    virtual bool executable_path(Process, ByteString &) = 0;
    virtual bool creation_time_milliseconds(Process, std::int64_t &) = 0;
    virtual bool reported_admin_flag(std::int32_t pid) = 0;        // token query @0xf33c80
    virtual bool reported_signed_flag(const ByteString &path) = 0; // cached helper @0xf43120
    virtual std::int64_t nanoseconds_since_creation(std::int64_t unix_seconds) = 0;
    virtual ByteString duration_string(std::int64_t nanoseconds) = 0;
    virtual ByteString format_local_time(std::int64_t unix_seconds, const ByteString &layout) = 0;
};
static ByteString go_bool(bool value) { return value ? "true" : "false"; }
// UAy9caHUbZ.NcvL2Kf92Y @0xf33380.
ByteString running_process_report(ProcessReportContracts &r) {
    std::vector<ProcessReportContracts::Process> processes;
    if (!r.processes(processes))
        return "none";
    const auto labels = r.window_labels();
    std::vector<ByteString> lines;
    for (const auto process : processes) {
        ByteString path;
        if (!r.executable_path(process, path))
            continue;
        const bool admin = r.reported_admin_flag(process.pid);
        std::int64_t created_ms;
        if (!r.creation_time_milliseconds(process, created_ms))
            continue;
        const auto created_seconds = created_ms / 1000;
        const auto elapsed = r.nanoseconds_since_creation(created_seconds);
        const auto elapsed_rounded = (elapsed / 1000000000LL) * 1000000000LL;
        const auto ago = r.duration_string(elapsed_rounded);
        const bool signed_flag = r.reported_signed_flag(path);
        const auto found = labels.find(process.pid);
        const auto label =
            (found == labels.end() || found->second.empty()) ? ByteString("N/A") : found->second;
        const auto started = r.format_local_time(created_seconds, "2006-01-02T15:04:05Z07:00");
        lines.push_back(path + " [" + std::to_string(process.pid) + "] | ADMIN:" + go_bool(admin) +
                        " | STARTED:" + started + " | AGO:" + ago +
                        " | SIGNED:" + go_bool(signed_flag) + " | WINDOW:" + label);
    }
    ByteString result;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i)
            result += '\n';
        result += lines[i];
    }
    return result;
}
} // namespace ocean::reconstructed
