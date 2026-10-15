#include "../../session/session_types.hpp"
#include <memory>
namespace ocean::reconstructed::minecraft_native_collection_review {
// Recovered: top-level native class collection opens a process context, selects
// the first case-insensitive jvm.dll module, loads VMStructs, walks classes, runs
// postprocessing, and closes the process handle on every normal return path.
using Word = std::uint64_t;
struct Error {
    Word type = 0, data = 0;
    bool present() const { return type != 0; }
};
struct Module {
    Word base = 0, size = 0;
    ByteString path;
};
struct Context {
    Word handle = 0;
    std::vector<Module> modules;
};
struct ClassSlice {
    Word data = 0;
    GoInt length = 0, capacity = 0;
}; // 320-byte originalrecords
struct Collected {
    ClassSlice value{};
    Error error{};
};
struct ContextResult {
    std::shared_ptr<Context> value;
    Error error;
};
struct LayoutResult {
    Word value = 0;
    Error error;
};
struct Contracts {
    virtual ContextResult original_context(std::uint32_t) = 0; // q4
    virtual Error original_close_handle(Word) = 0;
    virtual ByteString original_windows_basename(const ByteString &) = 0;         // FAq@1d6bc0
    virtual bool original_equal_fold(const ByteString &, const ByteString &) = 0; // Dqr@247ea0
    virtual Error original_error_string(const ByteString &) = 0;
    virtual Error original_wrap_error_or_format_literal(const ByteString &, Error) = 0;
    virtual LayoutResult original_load_vmstructs(Context &, const Module &) = 0;  // scygy4g
    virtual Word original_new_reader(Context &, Word layout) = 0;                 // piP0hJP
    virtual Collected original_class_walk(Word reader) = 0;                       // eigNN1NY
    virtual void original_postprocess_class_records(Word reader, ClassSlice) = 0; // i2VRLvrp
};
// Recovered oyNL.deferwrap1@1ab79a0: close a nonzero handle, clear it, and ignore
// any close error.
void close_context(Contracts &r, Context &context) {
    if (context.handle) {
        r.original_close_handle(context.handle);
        context.handle = 0;
    }
}
// Recovered oyNL@1ab6d60: basename must equal "jvm.dll" under Unicode EqualFold.
// The first matching module wins; the basename helper rejects directory-only paths.
Collected collect_classes(Contracts &r, std::uint32_t pid) {
    auto opened = r.original_context(pid);
    if (opened.error.present())
        return {{}, opened.error};
    auto &context = *opened.value;
    const Module *selected = nullptr;
    for (const auto &module : context.modules) {
        if (r.original_equal_fold(r.original_windows_basename(module.path), "jvm.dll")) {
            selected = &module;
            break;
        }
    }
    if (!selected) {
        const auto error =
            r.original_error_string("hotspot: jvm.dll is absent from the process module list");
        close_context(r, context);
        return {{}, error};
    }
    const auto layout = r.original_load_vmstructs(context, *selected);
    if (layout.error.present()) {
        const auto error =
            r.original_wrap_error_or_format_literal("hotspot: load VMStructs: %w", layout.error);
        close_context(r, context);
        return {{}, error};
    }
    const auto reader = r.original_new_reader(context, layout.value);
    auto result = r.original_class_walk(reader);
    if (!result.error.present())
        r.original_postprocess_class_records(reader, result.value);
    close_context(r, context);
    return result;
}
// Recovered: a walk error preserves its partial slice and skips postprocessing;
// the upstream PID cache then discards that partial result and does not cache it.
// The original Go routine registers CloseHandle with defer before module selection.
// Explicit calls above model normal returns only.
// Unresolved: panic/unwind cleanup remains a Go runtime contract rather than
// speculative C++ exception handling.
} // namespace ocean::reconstructed::minecraft_native_collection_review
