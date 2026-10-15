#include "../../common/review_contracts.hpp"
#include <memory>
namespace ocean::reconstructed {
// Recovered: enumerate visible top-level windows and stop at the first class name
// containing the exact substring "ad_win#3". Class-name length and EnumWindows
// status are ignored; the output is a single boolean.
struct WindowContracts {
    virtual bool is_window_visible(std::uint64_t hwnd) = 0;
    virtual std::uint32_t get_class_name_w(std::uint64_t hwnd,
                                           std::vector<std::uint16_t> &buffer) = 0;
    virtual ByteString utf16_to_go_string(const std::vector<std::uint16_t> &) = 0;
    virtual std::uint64_t make_callback(const std::function<std::uint64_t(std::uint64_t)> &) = 0;
    virtual std::uint64_t enum_windows(std::uint64_t callback, std::uint64_t parameter) = 0;
};
// Original callback UAy9caHUbZ.B8wvadN5.func1 @0xf1c1a0.
// GetClassNameW reads the window class, not its title. Buffer is 256 UTF16 units.
std::uint64_t window_class_check(WindowContracts &windows, std::uint64_t hwnd, bool &found) {
    if (!windows.is_window_visible(hwnd))
        return 1;
    std::vector<std::uint16_t> class_buffer(256, 0);
    (void)windows.get_class_name_w(hwnd, class_buffer); // Original ignores returned length.
    const auto class_name = windows.utf16_to_go_string(class_buffer);
    if (class_name.find("ad_win#3") != ByteString::npos) {
        found = true;
        return 0;
    }
    return 1;
}
// Original UAy9caHUbZ.B8wvadN5 @0xf1c0c0; report key is anydesk_ss.
bool visible_window_class_provider(WindowContracts &windows) {
    auto found = std::make_shared<bool>(false); // Original bool escapes into callback storage.
    const auto callback = windows.make_callback([&windows, found](std::uint64_t hwnd) {
        return window_class_check(windows, hwnd, *found);
    });
    (void)windows.enum_windows(callback, 0); // Original ignores error/result.
    return *found;
}
} // namespace ocean::reconstructed
