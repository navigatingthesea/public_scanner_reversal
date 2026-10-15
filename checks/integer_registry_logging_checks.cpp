#include "../session/session_types.hpp"

// Recovered behavior summary:
//   Input: DisablePca, NGenAssemblyUsageLog, and EnableActivityFeed integer reads.
//   Gate: For each callback, any successful read matches; number and registry kind are ignored.
//   Output: Appends the corresponding logging-disabled warning.
//   Failure: Open/read failure suppresses output; close failure preserves a prior warning.

namespace ocean::reconstructed::integer_registry_warning_review {
using Word = std::uint64_t;
struct Error { Word type = 0, data = 0; bool present() const { return type != 0; } };
struct OpenKey {
    Word handle = 0;
    Error error;
};
struct IntegerValue {
    Word number = 0;
    std::uint32_t kind = 0;
    Error error;
};
struct Contracts {
    virtual OpenKey original_open_registry(Word root, const ByteString& key,
                                           std::uint32_t access) = 0;
    virtual IntegerValue original_get_integer_value(Word key, const ByteString& name) = 0;
    virtual Error original_close_registry(Word key) = 0;
    virtual bool original_missing_value_error_comparison(Error) = 0;
    virtual void append_warning(const ByteString&) = 0; // WARNINGS, global572e7a0
    virtual void original_callback_timing_and_recovery_contract() = 0;
};

// These three callbacks test whether GetIntegerValue succeeded. They never
// compare the returned NUMBER or registry KIND. In particular, zero and one
// produce the same warning. Warning wording does not prove logging is disabled.
// The registry getter's real type/length validation remains its own contract.
void check_integer_value_presence(Contracts& runtime, const ByteString& key_path,
                                  const ByteString& value_name,
                                  const ByteString& warning) {
    const auto opened = runtime.original_open_registry(0x80000002, key_path, 0x20019);
    if (opened.error.present()) {
        runtime.original_callback_timing_and_recovery_contract();
        return;
    }
    const auto read = runtime.original_get_integer_value(opened.handle, value_name);
    if (!read.error.present()) {
        runtime.append_warning(warning);
    } else {
        // Original compares one captured missing-value error interface. Both
        // equality outcomes return without warning; retain the comparison as
        // a runtime contract rather than assigning an unproved error constant.
        (void)runtime.original_missing_value_error_comparison(read.error);
    }
    (void)runtime.original_close_registry(opened.handle); // ignored close error
    runtime.original_callback_timing_and_recovery_contract();
}

// ZlDbsI9 @12a24e0, dispatcher label PcaBypass.
void check_pca_policy(Contracts& runtime) {
    check_integer_value_presence(runtime,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat", "DisablePca",
        "Pca File logging disabled");
}
// QVUohz43oK @125dce0, dispatcher label NetBypass.
void check_dotnet_usage_log_setting(Contracts& runtime) {
    check_integer_value_presence(runtime,
        "SOFTWARE\\Microsoft\\.NETFramework", "NGenAssemblyUsageLog",
        "C# Apps run-log disabled");
}
// AAcXOJQI1iy @125aee0, dispatcher label ActivitiesCache.
void check_activity_feed_policy(Contracts& runtime) {
    check_integer_value_presence(runtime,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "EnableActivityFeed",
        "ActivitiesCache.db logging disabled");
}
//30 original callback fixtures returned under intercepted registry/timing/
//normal nil-recover providers. All integer values0,1,2,3,UINT32_MAX,UINT64_MAX
//warn on successful read; synthetic success with unrelated kind is also ignored
//by these callers. Open/read errors suppress warnings; close error preserves it.
//No actual registry, network, process, driver, sample or reconstructed C++ run.
//Go panic/defer/GC/concurrent append and original registry getter are contracts.
}
