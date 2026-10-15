#include "../session/session_types.hpp"
#include <functional>
namespace ocean::reconstructed::service_account_config_reader {
// Recovered: open SCM/service handles, query basic plus description/delayed/SID
// configuration, and return only the service start-account string. Query failures
// propagate; a recovered panic can return an empty account with a nil error.
using Handle = std::uint64_t;
struct Error {
    bool present = false, is_syscall_errno = false;
    std::uint64_t value = 0;
};
template <class T> struct Read {
    T value{};
    Error error;
};
struct Config {
    std::uint32_t service_type = 0, start_type = 0, error_control = 0, tag_id = 0, sid_type = 0;
    ByteString binary_path, load_order_group, start_account, display_name, description;
    std::vector<ByteString> dependencies;
    bool delayed_auto_start = false;
};
struct Native {
    virtual Read<Handle> open_scm_local(std::uint32_t access) = 0;
    virtual Read<Handle> open_service_utf16(Handle, const ByteString &, std::uint32_t access) = 0;
    virtual void close_service_handle_ignoring_error(Handle) = 0;
    virtual Error query_config_w(Handle, Bytes &buffer, std::uint32_t &bytes_needed) = 0;
    virtual Error query_config2_w(Handle, std::uint32_t level, Bytes &buffer,
                                  std::uint32_t &bytes_needed) = 0;
    virtual std::uint32_t unsafe_u32(const Bytes &, std::size_t offset) = 0;
    virtual std::uint64_t unsafe_u64(const Bytes &, std::size_t offset) = 0;
    virtual ByteString utf16_pointer_to_string(std::uint64_t) = 0;
    virtual std::vector<ByteString> utf16_multisz(std::uint64_t) = 0;
    virtual void panic_bounds() = 0;
    virtual void panic_error_type_assertion() = 0;
    virtual void recover(const std::function<void()> &, const std::function<void()> &) = 0;
    virtual void print_fields(const std::vector<ByteString> &) = 0;
};
Read<Bytes> query_buffer(Native &rt, Handle service, bool extended, std::uint32_t level) {
    std::uint32_t needed = 1024;
    for (;;) {
        const auto size = needed;
        Bytes buffer(size);
        if (size == 0)
            rt.panic_bounds();
        auto error = extended ? rt.query_config2_w(service, level, buffer, needed)
                              : rt.query_config_w(service, buffer, needed);
        if (!error.present)
            return {std::move(buffer), {}}; // returns ALLOCATED length, not needed
        if (!error.is_syscall_errno)
            rt.panic_error_type_assertion();
        if (error.value != 122 || needed <= size)
            return {{}, error};
    }
}
Read<Config> read_config(Native &rt, Handle service) { // Config@b84580, helper@b84b00
    auto raw = query_buffer(rt, service, false, 0);
    if (raw.error.present)
        return {{}, raw.error};
    auto description = query_buffer(rt, service, true, 1);
    if (description.error.present)
        return {{}, description.error};
    if (description.value.empty())
        rt.panic_bounds();
    auto delayed = query_buffer(rt, service, true, 3);
    if (delayed.error.present)
        return {{}, delayed.error};
    if (delayed.value.empty())
        rt.panic_bounds();
    auto sid = query_buffer(rt, service, true, 5);
    if (sid.error.present)
        return {{}, sid.error};
    if (sid.value.empty())
        rt.panic_bounds();
    Config c;
    c.service_type = rt.unsafe_u32(raw.value, 0);
    c.start_type = rt.unsafe_u32(raw.value, 4);
    c.error_control = rt.unsafe_u32(raw.value, 8);
    c.binary_path = rt.utf16_pointer_to_string(rt.unsafe_u64(raw.value, 16));
    c.load_order_group = rt.utf16_pointer_to_string(rt.unsafe_u64(raw.value, 24));
    c.tag_id = rt.unsafe_u32(raw.value, 32);
    c.dependencies = rt.utf16_multisz(rt.unsafe_u64(raw.value, 40));
    c.start_account = rt.utf16_pointer_to_string(rt.unsafe_u64(raw.value, 48));
    c.display_name = rt.utf16_pointer_to_string(rt.unsafe_u64(raw.value, 56));
    c.description = rt.utf16_pointer_to_string(rt.unsafe_u64(description.value, 0));
    c.delayed_auto_start = rt.unsafe_u32(delayed.value, 0) != 0;
    c.sid_type = rt.unsafe_u32(sid.value, 0);
    return {std::move(c), {}};
}
Read<ByteString> read_account(Native &rt, const ByteString &service) { // r2rH1AJ@12bdc20
    Read<ByteString> result{};
    rt.recover(
        [&] {
            auto manager = rt.open_scm_local(0xf003f);
            if (manager.error.present) {
                result.error = manager.error;
                return;
            }
            struct Close {
                Native &rt;
                Handle handle;
                ~Close() { rt.close_service_handle_ignoring_error(handle); }
            } close_manager{rt, manager.value};
            auto handle = rt.open_service_utf16(manager.value, service, 0xf01ff);
            if (handle.error.present) {
                result.error = handle.error;
                return;
            }
            Close close_service{rt, handle.value};
            auto config = read_config(rt, handle.value);
            if (config.error.present) {
                result.error = config.error;
                return;
            }
            result.value = config.value.start_account; // all other queried config fields discarded
        },
        [&] {
            rt.print_fields(
                {"Crash", "getServiceConfig", "Failed getting config for service: " + service});
        });
    return result; // panic before assignment can return EMPTY account with NIL error
}
// Native API contracts are ordinary SCM queries, not sample execution. UTF16
// conversion failure prevents OpenService. Handles close service then manager.
// Config2 description/delayed/SID failures discard account even if basic query
// succeeded. No history or account SID lookup. Query buffers start1024 and retry
// only syscall.Errno122 with strictly larger needed size; no explicit size cap.
// Recovered: twenty instruction routes cover 17 returns, including recovery and
// query growth, plus three synthetic
// empty-provider bounds boundaries (normal QueryConfig2 helper returns >=1024).
// Raw native UTF16 pointers are read without added structure bounds validation.
// Guest-only source; never compiled/run. Panic runtime cleanup is explicit.
} // namespace ocean::reconstructed::service_account_config_reader
