#include "../session/session_types.hpp"
#include <bit>
#include <variant>
// Recovered behavior summary:
//   Input: Loaded kernel modules, earliest PID 4 thread times, boot time, and five reference-driver
//          names.
//   Gate: Reports missing exact-case bam.sys; otherwise compares BAM to boot (>180s) or the
//         reference mean (>300s absolute difference).
//   Output: Emits BAM_DriverMissing, BAM_LateStart, or BAM_Restarted debug/report output.
//   Failure: Missing BAM time or unusable references can suppress timing output; arithmetic wrap
//            and last-BAM selection are preserved.

namespace ocean::reconstructed::shared_bam_timing {

struct GoTime {
    std::uint64_t wall;
    std::int64_t ext;
    std::uintptr_t location;

    bool zero() const { return wall == 0 && ext == 0; }
};

struct Duration {
    std::int64_t ns;
};

struct GoInt {
    std::int64_t value;
};

using Debug = std::variant<ByteString, GoTime, Duration, GoInt>;

struct Module56 {
    ByteString filename;
    std::uint64_t base;
    std::uint64_t end;
    GoTime earliest_thread;
};

struct Contracts {
    virtual std::vector<Module56> collect_loaded_modules() = 0;
    virtual void add_earliest_system_thread_time(std::vector<Module56>&) = 0;
    virtual std::int64_t time_subtract_ns(GoTime, GoTime) = 0;
    virtual std::int64_t time_since_ns(GoTime) = 0;
    virtual void console_report(const ByteString&) = 0;
    virtual void append_debug(const std::vector<Debug>&) = 0;
};

static std::int64_t wrap_add(std::int64_t left, std::int64_t right) {
    return std::bit_cast<std::int64_t>(
        std::uint64_t(left) + std::uint64_t(right));
}

static std::int64_t wrap_subtract(std::int64_t left, std::int64_t right) {
    return std::bit_cast<std::int64_t>(
        std::uint64_t(left) - std::uint64_t(right));
}

void check(Contracts& runtime,
           GoTime shared_boot,
           const std::vector<ByteString>& reference_names) {
    // TFi33xK7SYA @ 0x125b180
    auto modules = runtime.collect_loaded_modules();
    const Module56* bam = nullptr;
    for (const auto& module : modules) {
        if (module.filename == "bam.sys") {
            bam = &module;
        }
    }

    if (bam == nullptr) {
        runtime.console_report(
            "BAM Bypass:::Driver missing:::BAM driver not found in kernel space");
        runtime.append_debug({
            ByteString("Detect"),
            ByteString("BAM_DriverMissing"),
            GoInt{static_cast<std::int64_t>(modules.size())},
        });
        return; // no process/thread query when the driver is absent
    }

    runtime.add_earliest_system_thread_time(modules);
    bam = nullptr;
    std::vector<Module56> references;
    for (const auto& module : modules) {
        if (module.filename == "bam.sys") {
            bam = &module; // last exact-case match wins
        }
        if (module.earliest_thread.zero()) {
            continue;
        }
        for (const auto& reference_name : reference_names) {
            if (reference_name == module.filename) {
                references.push_back(module);
                break;
            }
        }
    }

    if (bam == nullptr || bam->earliest_thread.zero()) {
        return;
    }

    const auto bam_after_boot =
        runtime.time_subtract_ns(bam->earliest_thread, shared_boot);
    if (references.empty()) {
        if (bam_after_boot > 180000000000LL) {
            const auto age = runtime.time_since_ns(bam->earliest_thread);
            runtime.console_report(
                "BAM Bypass:::Boot instance:::BAM started after boot");
            runtime.append_debug({
                ByteString("Detect"),
                ByteString("BAM_LateStart"),
                bam->earliest_thread,
                Duration{bam_after_boot},
                Duration{age},
            });
        }
        return;
    }

    std::int64_t reference_sum = 0;
    for (const auto& reference : references) {
        reference_sum = wrap_add(
            reference_sum,
            runtime.time_subtract_ns(reference.earliest_thread, shared_boot));
    }
    // Integer division truncates toward zero; this is a mean, not a median.
    const auto reference_mean =
        reference_sum / static_cast<std::int64_t>(references.size());

    auto difference = wrap_subtract(bam_after_boot, reference_mean);
    if (difference < 0) {
        difference = wrap_subtract(reference_mean, bam_after_boot);
        // INT64_MIN wrap behavior is intentionally retained.
    }
    if (difference > 300000000000LL) {
        const auto age = runtime.time_since_ns(bam->earliest_thread);
        runtime.console_report(
            "BAM Bypass:::Boot instance:::BAM restarted after boot");
        runtime.append_debug({
            ByteString("Detect"),
            ByteString("BAM_Restarted"),
            bam->earliest_thread,
            Duration{bam_after_boot},
            Duration{reference_mean},
            Duration{difference},
            Duration{age},
        });
    }
}

std::vector<ByteString> captured_reference_names() {
    // Captured slice words at RVAs 0x56631f0/0x56631f8/0x5663200.
    return {"ntfs.sys", "volmgr.sys", "disk.sys", "ndis.sys", "tcpip.sys"};
}

// Sixteen original callback routes cover exact thresholds, case sensitivity,
// duplicate BAM selection, zero times, and the earlier-than-reference branch.
// The thread creation times are inputs to a heuristic; they do not prove a
// driver load or restart. There is no warning-slice append, history comparison,
// direct BAM registry/file lookup, or callback panic recovery in this root.

}  // namespace ocean::reconstructed::shared_bam_timing
