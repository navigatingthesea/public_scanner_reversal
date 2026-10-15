#include "../session/session_types.hpp"
#include <bit>
#include <functional>
// Recovered behavior summary:
//   Input: NtQuerySystemInformation class 11 module records and class 5 process/thread records.
//   Gate: The second query must return exactly zero; threads are considered only under PID 4 and
//         are assigned to the first half-open module address range.
//   Output: Returns every decoded module and annotates it with the earliest matching system-thread
//           creation time.
//   Failure: A zero size or nonzero second-query status returns no data; the recovered code keeps
//            its narrow bounds checks and wraparound arithmetic.

namespace ocean::reconstructed::bam_module_thread_providers {

struct GoTime {
    std::uint64_t wall;
    std::int64_t ext;
    std::uintptr_t location;

    bool zero() const { return wall == 0 && ext == 0; }
};

struct Module56 {
    ByteString filename;
    std::uint64_t base;
    std::uint64_t end;
    GoTime earliest_thread;
};

using Buffer = std::uintptr_t;

struct Contracts {
    virtual std::uintptr_t query_system_information(
        std::uint64_t information_class,
        Buffer buffer,
        std::uint32_t capacity,
        std::uint32_t& needed) = 0;
    // Captured LazyProc 0x5728dc8. The NtQuerySystemInformation role is
    // inferred from the ABI and information classes 11 and 5.
    virtual Buffer make_zero_byte_slice(std::uint32_t length) = 0;
    virtual std::uint16_t unsafe_u16(Buffer, std::uint64_t) = 0;
    virtual std::uint32_t unsafe_u32(Buffer, std::uint64_t) = 0;
    virtual std::uint64_t unsafe_u64(Buffer, std::uint64_t) = 0;
    virtual ByteString unsafe_bytes_until_nul_or_length(
        Buffer, std::uint64_t, std::size_t) = 0;
    virtual void go_panic_bounds() = 0;
    virtual GoTime go_unix_zero_plus_nanoseconds(std::int64_t) = 0;
    virtual bool time_before(GoTime, GoTime) = 0;
};

GoTime filetime(Contracts& runtime, std::uint64_t value) { // e9pYDGlBVg @ 0x125dbe0
    const auto wrapped = value * 100ULL + 0x5e6684f4b3960000ULL;
    return runtime.go_unix_zero_plus_nanoseconds(
        std::bit_cast<std::int64_t>(wrapped));
    // Multiply/subtract wraps before Unix normalization. Go Unix returns a
    // normalized second/nanosecond pair and a Local location pointer.
}

std::vector<Module56> collect(Contracts& runtime) { // uFaiG06q7m @ 0x125d540
    std::uint32_t needed = 0;
    runtime.query_system_information(11, 0, 0, needed); // status ignored
    if (needed == 0) {
        return {};
    }

    const std::uint32_t length = needed + 0x10000U; // 32-bit wrap
    const auto buffer = runtime.make_zero_byte_slice(length);
    if (length == 0) {
        runtime.go_panic_bounds();
    }
    if (runtime.query_system_information(11, buffer, length, needed) != 0) {
        return {};
    }

    const auto count = runtime.unsafe_u32(buffer, 0);
    std::vector<Module56> result;
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto offset = std::uint64_t(index) * 0x128;
        if (length <= offset + 8) {
            runtime.go_panic_bounds(); // only original explicit index gate
        }

        const auto filename_offset = runtime.unsafe_u16(buffer, offset + 0x2e);
        if (filename_offset > 256) {
            runtime.go_panic_bounds();
        }
        const auto filename = runtime.unsafe_bytes_until_nul_or_length(
            buffer, offset + 0x30 + filename_offset, 256 - filename_offset);
        const auto base = runtime.unsafe_u64(buffer, offset + 24);
        const auto image_size = runtime.unsafe_u32(buffer, offset + 32);
        result.push_back({filename, base, base + image_size, {}});
        // The end-address addition wraps and the name is not normalized.
    }
    return result;
}

void enrich(Contracts& runtime,
            std::vector<Module56>& modules) { // zWqYigO_p @ 0x125d8e0
    std::uint32_t needed = 0;
    runtime.query_system_information(5, 0, 0, needed); // status ignored
    if (needed == 0) {
        return;
    }

    const std::uint32_t length = needed + 0x100000U;
    const auto buffer = runtime.make_zero_byte_slice(length);
    if (length == 0) {
        runtime.go_panic_bounds();
    }
    if (runtime.query_system_information(5, buffer, length, needed) != 0) {
        return;
    }

    std::uint64_t process_offset = 0;
    for (;;) {
        if (length <= process_offset) {
            runtime.go_panic_bounds();
        }
        if (runtime.unsafe_u64(buffer, process_offset + 0x50) == 4) {
            break;
        }
        const auto next_offset = runtime.unsafe_u32(buffer, process_offset);
        if (next_offset == 0) {
            return;
        }
        process_offset += next_offset;
    }

    const auto thread_count = runtime.unsafe_u32(buffer, process_offset + 4);
    auto thread_offset = process_offset + 0x100;
    for (std::uint32_t index = 0; index < thread_count;
         ++index, thread_offset += 0x50) {
        if (length <= thread_offset) {
            runtime.go_panic_bounds();
        }
        const auto start_address =
            runtime.unsafe_u64(buffer, thread_offset + 0x20);
        for (auto& module : modules) {
            // The first matching interval wins; the end address is exclusive.
            if (module.base <= start_address && start_address < module.end) {
                const auto created = filetime(
                    runtime, runtime.unsafe_u64(buffer, thread_offset + 0x10));
                if (module.earliest_thread.zero() ||
                    runtime.time_before(created, module.earliest_thread)) {
                    module.earliest_thread = created;
                }
                break;
            }
        }
    }
}

// Twenty-one original provider routes cover size/status handling, module names,
// address wrap, PID 4 traversal, and earliest-thread selection. Seven FILETIME
// leaf routes separately confirm the wrapped Unix conversion. The recovered
// code does not validate complete record spans after its limited slice guards,
// retry a short buffer, or interpret NTSTATUS by sign; the second query must
// return exactly zero.

}  // namespace ocean::reconstructed::bam_module_thread_providers
