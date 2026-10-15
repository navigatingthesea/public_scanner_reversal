#include "../lua/query_records.hpp"
#include <array>
#include <functional>
namespace ocean::reconstructed::service_pid_review {
// Recovered: open one service, size and read SERVICE_STATUS_PROCESS, and return
// the ProcessId DWORD at offset 28. Any ordinary SCM/query error returns zero;
// zero required length and empty UTF-16 conversion retain original panic behavior.
using ByteString = lua_review::ByteString;
struct Error {
    std::uint64_t original_type = 0, original_data = 0;
    explicit operator bool() const { return original_type != 0; }
};
struct ServicePidContracts {
    using Handle = std::uint64_t;
    struct Buffer {
        std::uint64_t data = 0;
        std::uint32_t length = 0;
    };
    struct Defers {
        virtual ~Defers() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~ServicePidContracts() = default;
    virtual std::uint32_t
    original_go_defer_scope(const std::function<std::uint32_t(Defers &)> &) = 0;
    virtual Error open_sc_manager_null_names(std::uint32_t access, Handle &) = 0;
    virtual void close_service_handle(Handle) = 0;
    // Original UTF16FromString result; its error is discarded by this caller.
    virtual std::vector<std::uint16_t>
    original_utf16_from_string_ignoring_error(const ByteString &) = 0;
    [[noreturn]] virtual void original_panic_bounds() = 0;
    virtual Error open_service(Handle, const std::vector<std::uint16_t> &name, std::uint32_t access,
                               Handle &) = 0;
    virtual Error query_service_status_ex(Handle, std::uint32_t info_level, Buffer,
                                          std::uint32_t &needed) = 0;
    virtual bool is_exact_syscall_errno(Error, std::uint64_t) = 0;
    virtual Buffer original_byte_allocation(std::uint32_t needed) = 0;
    // The original copies36 bytes when needed>0, even if needed<36. Preserve
    // that original read boundary as a contract, rather than adding a size check.
    virtual std::array<std::uint8_t, 36> original_copy_service_status_36_bytes(Buffer) = 0;
};
// NN9p33oaT@f244a0; original native wrappers@4cc1e0/4cc2e0/4cc640.
std::uint32_t query_service_pid(ServicePidContracts &r, const ByteString &name) {
    return r.original_go_defer_scope([&](ServicePidContracts::Defers &defers) -> std::uint32_t {
        ServicePidContracts::Handle manager = 0;
        if (r.open_sc_manager_null_names(1, manager))
            return 0; // SC_MANAGER_CONNECT
        defers.add([&r, manager] { r.close_service_handle(manager); });
        const auto wide = r.original_utf16_from_string_ignoring_error(name);
        if (wide.empty())
            r.original_panic_bounds();
        ServicePidContracts::Handle service = 0;
        if (r.open_service(manager, wide, 4, service))
            return 0; // SERVICE_QUERY_STATUS
        defers.add([&r, service] { r.close_service_handle(service); });
        std::uint32_t needed = 0;
        const auto probe = r.query_service_status_ex(service, 0, {}, needed);
        if (probe && !r.is_exact_syscall_errno(probe, 122))
            return 0; // ERROR_INSUFFICIENT_BUFFER
        const auto buffer =
            r.original_byte_allocation(needed); // original stack capacity32 else makeslice
        if (needed == 0)
            r.original_panic_bounds();
        if (r.query_service_status_ex(service, 0, buffer, needed))
            return 0;
        const auto status = r.original_copy_service_status_36_bytes(buffer);
        // f246b4..f246cb copies36B; f246d0 selects offset28 ProcessId DWORD.
        return std::uint32_t(status[28]) | std::uint32_t(status[29]) << 8 |
               std::uint32_t(status[30]) << 16 | std::uint32_t(status[31]) << 24;
    });
}
} // namespace ocean::reconstructed::service_pid_review

// Additional original-instruction validation: eight normal routes plus the
// zero-required-length bounds panic. Comparable syscall.Errno is compared by
// numeric value; a successful initial sizing call is also accepted. The old
// f246b4..f246cb 36-byte COPY is retained, including needed32. Those controlled
// stack-backed fixtures do not establish memory safety for short buffers.
// Native/service/C++ execution was never performed.
