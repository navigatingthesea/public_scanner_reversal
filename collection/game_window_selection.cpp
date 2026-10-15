#include "../lua/query_records.hpp"
#include <array>
#include <cstring>
#include <functional>
#include <memory>
namespace ocean::reconstructed::game_window_selection_review {
// Recovered: enumerate top-level windows once, compare each visible window class
// exactly against every configured filter, and return the first title for each
// signed PID in callback order. PID zero is accepted; EnumWindows status is ignored
// and any partial accumulated result is returned without sorting.
using ByteString = lua_review::ByteString;
template <class T> struct ReviewSlice {
    bool original_nil = true;
    std::vector<T> values;
};
struct InternalPidTitle {
    std::int64_t pid = 0;
    ByteString title;
}; // 24B originaltype366b520
struct SelectionState {
    std::vector<ByteString> class_filters;
    ReviewSlice<std::int64_t> seen{false, {}};              // initial nonnil zerobase, length0
    ReviewSlice<InternalPidTitle> internal_rows{false, {}}; // same, not returned
    ReviewSlice<ByteString> titles;
    ReviewSlice<std::int64_t> pids;
};
struct SelectionResult {
    ReviewSlice<std::int64_t> pids;
    ReviewSlice<ByteString> titles;
};
struct WindowSelectionContracts {
    using Hwnd = std::uint64_t;
    using Callback = std::uint64_t;
    using Wide256 = std::array<std::uint16_t, 256>;
    virtual ~WindowSelectionContracts() = default;
    virtual std::shared_ptr<Wide256> original_zeroed_utf16_array_allocation() = 0;
    virtual std::uint64_t is_window_visible(Hwnd) = 0;                             // 5727958
    virtual std::uint64_t get_class_name_w(Hwnd, Wide256 &, std::size_t) = 0;      // 5727950
    virtual std::uint64_t get_window_thread_process_id(Hwnd, std::uint32_t &) = 0; // 5727960
    virtual std::uint64_t get_window_text_w(Hwnd, Wide256 &, std::size_t) = 0;     // 5727968
    virtual ByteString original_utf16_to_string(
        const Wide256 &) = 0; // firstNUL or all256; invalid surrogates use originalGo decoder
    virtual void original_append_title(ReviewSlice<ByteString> &, const ByteString &) = 0;
    virtual void original_append_row(ReviewSlice<InternalPidTitle> &, const InternalPidTitle &) = 0;
    virtual void original_append_pid(ReviewSlice<std::int64_t> &, std::int64_t) = 0;
    // The Go callback compiler retains the heap closure; no callback release is
    // inserted. clean_stack=true was captured at 0x6cb7f9.
    virtual Callback register_original_windows_callback(const std::function<std::uint64_t(Hwnd)> &,
                                                        bool clean_stack) = 0;
    virtual std::uint64_t enum_windows(Callback, std::uint64_t lparam) = 0; // 5727948
    virtual SelectionResult copy_original_return_slice_headers(const SelectionState &) = 0;
};
// Recovered Db11aUZ.func1@0x6cb8a0: callback always returns 1 to continue enumeration.
std::uint64_t examine_game_window(WindowSelectionContracts &r, SelectionState &state,
                                  WindowSelectionContracts::Hwnd hwnd) {
    const auto class_buffer = r.original_zeroed_utf16_array_allocation();
    const auto title_buffer =
        r.original_zeroed_utf16_array_allocation(); // both before visibility check
    if (r.is_window_visible(hwnd) == 0)
        return 1;
    r.get_class_name_w(hwnd, *class_buffer, 256); // return length and native error discarded
    const auto class_name = r.original_utf16_to_string(*class_buffer);
    for (const auto &wanted : state.class_filters) {
        if (class_name != wanted)
            continue; // exact case-sensitive byte comparison
        std::uint32_t pid_bits = 0;
        r.get_window_thread_process_id(hwnd, pid_bits); // failure still leaves a usable0
        std::int32_t signed_pid = 0;
        std::memcpy(&signed_pid, &pid_bits, sizeof signed_pid);
        const std::int64_t pid = signed_pid; // original MOVSXD, not uint32 zero extension
        bool already_seen = false;
        for (const auto previous : state.seen.values)
            if (previous == pid) {
                already_seen = true;
                break;
            }
        if (already_seen)
            continue;
        r.get_window_text_w(hwnd, *title_buffer, 256); // length/status ignored
        const auto title = r.original_utf16_to_string(*title_buffer);
        // Preserve original append order; a runtime panic can leave partial state.
        r.original_append_title(state.titles, title);
        r.original_append_row(state.internal_rows, {pid, title});
        r.original_append_pid(state.pids, pid);
        r.original_append_pid(state.seen, pid);
        // Continue to next filter. A duplicate filter repeats the PID query, then
        // the seen check prevents another title query/output row.
    }
    return 1;
}
// Db11aUZ@6cb6e0 returns PID and title slice headers (48 original bytes).
SelectionResult select_game_windows(WindowSelectionContracts &r,
                                    const std::vector<ByteString> &class_filters) {
    auto state = std::make_shared<SelectionState>();
    state->class_filters = class_filters;
    const auto callback = r.register_original_windows_callback(
        [&r, state](auto hwnd) { return examine_game_window(r, *state, hwnd); }, true);
    r.enum_windows(callback,
                   0); // BOOL and native error ignored; partial accumulated result returned
    return r.copy_original_return_slice_headers(*state); // empty output slices remainnil
}
} // namespace ocean::reconstructed::game_window_selection_review
