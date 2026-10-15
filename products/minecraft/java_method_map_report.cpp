#include "../../transport/shared_gzip_payload.hpp"

namespace ocean::reconstructed::minecraft_method_map_report_review {
using gzip_payload_review::ByteResult;
using gzip_payload_review::ByteSlice;
using gzip_payload_review::ErrorWords;

struct CollectedMap {
    std::uint64_t original_map_identity = 0;
    ErrorWords error;
};

struct ReportContracts {
    virtual CollectedMap original_pid_class_member_map(std::uint32_t) = 0; // ky4aEt.ZQPDWj
    virtual ByteString original_trim_unicode_space(const ByteString&) = 0;
    virtual bool original_equal_fold(const ByteString&, const ByteString&) = 0; // Dqr@247ea0
    virtual void original_reviewed_unicode_method_check(std::uint64_t map_identity) = 0; // bcx@1c09140
    virtual ByteResult original_json_marshal_map_string_to_string_slice(
        std::uint64_t map_identity) = 0;
    virtual ByteResult original_reviewed_gzip_level9_helper(const ByteSlice&) = 0; // Eh22kL_@f24900
    virtual void original_log_error(const ByteString& label, const ErrorWords&) = 0;
    virtual void original_log_byte_sizes(
        const ByteString& label,
        GoInt json_size,
        GoInt gzip_size) = 0;
};

// QcBKMMBuwy8_@1c08500
ByteSlice collect_and_encode(
    ReportContracts& runtime,
    std::uint32_t pid,
    const ByteString& response_ru) {
    // Recovered: class/member collection always runs. The `ru` response option
    // controls only the unusual-Unicode check below.
    const auto collected = runtime.original_pid_class_member_map(pid);
    if (collected.error.present()) {
        runtime.original_log_error("JAVA_DEBUG_SCAN_ERROR", collected.error);
        return {};
    }

    const auto unicode_option = runtime.original_trim_unicode_space(response_ru);
    if (runtime.original_equal_fold(unicode_option, "true"))
        runtime.original_reviewed_unicode_method_check(collected.original_map_identity);

    // Recovered: serialize the complete map[string][]string, including entries
    // that did not contribute to the Unicode check.
    const auto json = runtime.original_json_marshal_map_string_to_string_slice(
        collected.original_map_identity);
    if (json.error.present()) {
        runtime.original_log_error("JAVA_DEBUG_SCAN_ERROR", json.error);
        return {};
    }

    const auto compressed = runtime.original_reviewed_gzip_level9_helper(json.value);
    if (compressed.error.present()) {
        runtime.original_log_error("JAVA_DEBUG_COMPRESSION_ERROR", compressed.error);
        return {};
    }

    runtime.original_log_byte_sizes(
        "JAVA_DEBUG_SIZE",
        static_cast<GoInt>(json.value.bytes.size()),
        static_cast<GoInt>(compressed.value.bytes.size()));
    return compressed.value;
}

// Recovered: after Unicode whitespace trimming, case-insensitive `true` enables
// the unusual-member-name check; substrings such as `untrue` do not. A check may
// append diagnostics even when later JSON or gzip processing fails; this caller
// does not roll those outputs back. Worker 33 stores the returned slice words at
// 0x572e5c0, 0x572e5c8, and 0x572e5d0.
//
// Unresolved: JSON key ordering, exact escaping, native map production, codec
// internals, and logger side effects remain provider behavior. Thirteen original
// caller fixtures were checked. This readable source was never compiled or run.
}
