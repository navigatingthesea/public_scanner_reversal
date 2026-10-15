#include "../../session/session_types.hpp"
namespace ocean::reconstructed::minecraft_native_method_classifier {
// Recovered: classify a resolved native Java method by remote memory region,
// backing-file existence, and whether its native slot still contains the same
// address. This gathers evidence; it does not choose a rule score.
struct Region {
    std::uint32_t state, protection, type;
};
struct Query {
    Region region;
    bool error;
};
struct PointerRead {
    std::uint64_t value;
    bool error;
};
struct Method {
    bool native_access_bit = false;           // method136 from original accessFlags bit8
    std::uint64_t native_address = 0;         // 208
    bool native_pointer_read_success = false; // 216, original TWO pointer reads succeed
    ByteString owner_module224, backing_path240;
    bool address_still_matches256 = false;
    bool region_query_succeeded257 = false;
    bool private_committed_executable258 = false;
    bool backing_path_missing259 = false;
};
struct Contracts {
    virtual Query query_remote_address(std::uint64_t) = 0;        // VirtualQueryEx error wrapper
    virtual bool stat_error_is_not_exist(const ByteString &) = 0; // original os.Stat+IsNotExist
    virtual PointerRead reread_original_native_slot(std::uint64_t) = 0;
};
void classify(Contracts &runtime, Method &method, std::uint64_t original_slot) { // fmtEC@1aa7f80
    // Original updates fields IN PLACE. It doesn't clear prior257..259 on skipped paths.
    if (method.native_address != 0) {
        const auto query = runtime.query_remote_address(method.native_address);
        if (!query.error) {
            method.region_query_succeeded257 = true;
            const auto &region = query.region;
            const auto base = region.protection & 0xff;
            const bool executable = base == 0x10 || base == 0x20 || base == 0x40 || base == 0x80;
            method.private_committed_executable258 = region.state == 0x1000 &&
                                                     region.type == 0x20000 &&
                                                     !(region.protection & 0x100) && executable;
        }
    }
    if (!method.backing_path240.empty())
        method.backing_path_missing259 = runtime.stat_error_is_not_exist(method.backing_path240);
    const auto reread = runtime.reread_original_native_slot(original_slot);
    method.address_still_matches256 = !reread.error && reread.value == method.native_address;
}
// Recovered: parent ndFCF9@1a490c0 constructs 296-byte method rows. It derives
// native_access_bit from access-flag bit 8; field 137 holds bit 10. Two pointer
// reads at the recovered native slot must succeed before the address is accepted,
// module ownership is resolved, and classify() receives the original slot. The
// parent traversal is in
// java_raw_method_control_flow.cpp.
// Recovered: the low protection byte must be 0x10, 0x20, 0x40, or 0x80; PAGE_GUARD
// rejects the region. Query success alone does not prove private executable memory.
// The helper updates fields in place and deliberately does not clear skipped flags.
} // namespace ocean::reconstructed::minecraft_native_method_classifier
