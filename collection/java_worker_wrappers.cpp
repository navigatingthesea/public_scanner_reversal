#include "../../common/review_contracts.hpp"
#include <array>
#include <functional>
namespace ocean::reconstructed {
// Recovered: workers 25..33 call fixed Java-analysis helpers, copy their exact
// return words into captured globals, optionally box response values, and always
// execute WaitGroup.Done through the recovered defer wrapper.
struct JavaWorkerContracts {
    using Words5 = std::array<std::uint64_t, 5>;
    using Words3 = std::array<std::uint64_t, 3>;
    virtual ~JavaWorkerContracts() = default;
    virtual Words5 invoke_original_helper(std::uint64_t rva, std::uint32_t argument = 0) = 0;
    virtual void store_word(std::uint64_t global_rva, std::uint64_t) = 0;
    virtual std::uint64_t image_address(std::uint64_t rva) = 0;
    virtual std::uint64_t box_typed_words(std::uint64_t type_rva, const Words5 &) = 0;
    virtual std::uint64_t box_string_slice(const Words3 &) = 0;
    virtual ByteString response_field_ru() = 0; // global0x5733450/458, JSON ru
    virtual void with_waitgroup_done_deferred(std::uint64_t group, std::function<void()>) = 0;
};
// Worker 25 @0x1f00be0; original callee gKUdZHIZpX.YQ0DOUzqZKt2 @0x1c4c260.
void java_worker_25(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(group, [&] {
        const auto result = r.invoke_original_helper(0x1c4c260);
        r.store_word(0x572b9b0, result[0]);
        r.store_word(0x572b9b8, result[1]);
    });
}
// Worker 26 @0x1f00aa0; original callee gKUdZHIZpX.A2IxgAT2 @0x1c14f60.
void java_worker_26(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(group, [&] {
        const auto result = r.invoke_original_helper(0x1c14f60);
        const auto boxed = r.box_typed_words(0x3672460, result);
        r.store_word(0x572b9c0, r.image_address(0x3672460));
        r.store_word(0x572b9c8, boxed);
    });
}
// Worker 27 @0x1f009e0; original callee gKUdZHIZpX.Z_1Z44g @0x1c40780.
void java_worker_27(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(
        group, [&] { const auto result = r.invoke_original_helper(0x1c40780); });
}
// Worker 28 @0x1f00920; original callee gKUdZHIZpX.TSCHoF @0x1c0ffe0.
void java_worker_28(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(
        group, [&] { const auto result = r.invoke_original_helper(0x1c0ffe0); });
}
// Recovered worker 29 @0x1f00820: WVSg94v@0x1c15b80 returns a string plus Go time.Time.
// result[2..4] stored5732210/18/20 are wall/ext/location, NOT a slice.
void java_worker_29(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(group, [&] {
        const auto result = r.invoke_original_helper(0x1c15b80);
        r.store_word(0x572b990, result[0]);
        r.store_word(0x572b998, result[1]);
        r.store_word(0x5732210, result[2]);
        r.store_word(0x5732218, result[3]);
        r.store_word(0x5732220, result[4]);
    });
}
// Worker 30 @0x1f00720; original callee gKUdZHIZpX.JEg1SQOq @0x1c5fa60.
void java_worker_30(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(group, [&] {
        const auto result = r.invoke_original_helper(0x1c5fa60);
        r.store_word(0x572e5a0, result[0]);
        r.store_word(0x572e5a8, result[1]);
        r.store_word(0x572e5b0, result[2]);
    });
}
// Worker 31 @0x1f00620; original callee gKUdZHIZpX.Kb98QVd @0x1c445a0.
void java_worker_31(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(group, [&] {
        const auto result = r.invoke_original_helper(0x1c445a0);
        const auto boxed = r.box_string_slice({result[0], result[1], result[2]});
        r.store_word(0x572b9a0, r.image_address(0x3578ae0));
        r.store_word(0x572b9a8, boxed);
    });
}
// Worker 32 @0x1f00540; original callee QaD5eK5_da.VDI1WlC @0x1e771c0.
void java_worker_32(JavaWorkerContracts &r, std::uint64_t group) {
    r.with_waitgroup_done_deferred(group, [&] {
        if (r.response_field_ru() == "true")
            r.invoke_original_helper(0x1e771c0);
    });
}
// Worker 33 @0x1f00440; original callee gKUdZHIZpX.QcBKMMBuwy8_ @0x1c08500.
void java_worker_33(JavaWorkerContracts &r, std::uint64_t group, std::uint32_t selected_pid) {
    r.with_waitgroup_done_deferred(group, [&] {
        const auto result = r.invoke_original_helper(0x1c08500, selected_pid);
        r.store_word(0x572e5c0, result[0]);
        r.store_word(0x572e5c8, result[1]);
        r.store_word(0x572e5d0, result[2]);
    });
}
} // namespace ocean::reconstructed
