#include "../../session/session_types.hpp"
namespace ocean::reconstructed::minecraft_native_module_owner {
// Recovered: attribute a native method address to the first enumerated module
// whose unsigned half-open address range contains it.
struct Module {
    std::uint64_t base, size;
    ByteString path;
};
struct Owner {
    ByteString basename, path;
};
struct Contracts {
    virtual ByteString original_windows_filepath_base(const ByteString &) = 0;
};
Owner identify(Contracts &runtime, const std::vector<Module> &modules, std::uint64_t address) {
    // y4j0@1a8b2c0 original unsigned comparisons, stride32. First input match wins.
    for (const auto &module : modules)
        if (module.base <= address && address < module.base + module.size)
            return {runtime.original_windows_filepath_base(module.path), module.path};
    return {};
}
// Recovered: uint64 addition wraps. Rewriting this as address-base < size would
// change the overflow behavior. Ranges are not sorted or lowercased, and overlaps
// resolve to the first input module. The parent stores basename at field 224 and
// full path at 240; later rules test the full path independently.
} // namespace ocean::reconstructed::minecraft_native_module_owner
