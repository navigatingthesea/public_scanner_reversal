#include "../../common/review_contracts.hpp"
namespace ocean::reconstructed {
// Recovered: run the hardware-query initializer once, then return one of two
// cached identity strings. The non-alternate branch also mirrors its value into
// a third global. The initializer body remains a recovered-reference dependency.
struct HardwareIdentityContracts {
    virtual ~HardwareIdentityContracts() = default;
    virtual void run_once(std::uint64_t once_global_rva, std::uint64_t callback_rva) = 0;
    virtual ByteString load_string(std::uint64_t global_rva) = 0;
    virtual void store_string(std::uint64_t global_rva, const ByteString &) = 0;
};
// UAy9caHUbZ.O7T_Vp @0xf3c3c0. The once callback @0xf3c480 performs
// the hardware queries/formatting; its body is preserved in recovered_reference.
ByteString hardware_identity(HardwareIdentityContracts &r, bool alternate) {
    r.run_once(0x577a8d0, 0xf3c480);
    if (alternate)
        return r.load_string(0x572ba00);
    auto value = r.load_string(0x572b9f0);
    r.store_string(0x572b8a0, value);
    return value;
}
} // namespace ocean::reconstructed
