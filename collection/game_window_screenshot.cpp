#include "../lua/query_records.hpp"
#include <functional>
#include <optional>
#include <cstring>
namespace ocean::reconstructed::window_capture_review {
// Recovered: find windows for each configured class, restore iconic windows,
// capture BGRA pixels through GDI, reject fully black RGB output, convert to
// top-down RGBA, encode JPEG quality 90 data URIs, and keep the longest successful result.
using ByteString = lua_review::ByteString;
struct GoError {
    std::uint64_t original_type = 0, original_data = 0;
};
using Error = std::optional<GoError>;
struct CaptureResult {
    ByteString encoded;
    Error error;
};
struct RgbaImage {
    std::vector<std::uint8_t> pixels;
    std::int64_t stride = 0;
};
struct WindowCaptureContracts {
    using Handle = std::uint64_t;
    struct Rect {
        std::int32_t left = 0, top = 0, right = 0, bottom = 0;
    };
    struct BitmapInfo { // captured Go bitmap-info object3642140,40B
        std::uint32_t size = 40;
        std::int32_t width = 0, height = 0;
        std::uint16_t planes = 1, bits = 32;
        std::uint32_t compression = 0, image_size = 0;
        std::int32_t x_pixels = 0, y_pixels = 0;
        std::uint32_t colors_used = 0, important_colors = 0;
    };
    struct DeferSink {
        virtual ~DeferSink() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~WindowCaptureContracts() = default;
    // Executes registered actions in LIFO order on returns AND Go panic unwinding.
    virtual CaptureResult
    with_original_go_defers(const std::function<CaptureResult(DeferSink &)> &) = 0;
    virtual bool is_visible(Handle) = 0;                        // IsWindowVisible5727c00
    virtual bool is_iconic(Handle) = 0;                         // IsIconic5727c30
    virtual void show_window(Handle, std::int64_t command) = 0; // ShowWindow5727c18, return ignored
    virtual void sleep_nanoseconds(std::int64_t) = 0;
    virtual bool get_client_rect(Handle, Rect &) = 0;      // GetClientRect5727c10
    virtual Handle get_dc(Handle) = 0;                     // GetDC565c5b8
    virtual void release_dc(Handle window, Handle dc) = 0; // ReleaseDC5727bf0
    virtual Handle compatible_dc(Handle) = 0;              // CreateCompatibleDC5727c40
    virtual void delete_dc(Handle) = 0;                    // DeleteDC5727c60
    virtual Handle compatible_bitmap(Handle, std::int64_t width,
                                     std::int64_t height) = 0;  // 5727c48
    virtual void delete_object(Handle) = 0;                     // DeleteObject5727c58
    virtual Handle select_object(Handle dc, Handle object) = 0; // SelectObject5727c50
    virtual bool print_window(Handle window, Handle memory_dc, std::uint64_t flags) = 0; // 5727c08
    virtual bool bit_blt(Handle dest, std::int64_t dx, std::int64_t dy, std::int64_t width,
                         std::int64_t height, Handle source, std::int64_t sx, std::int64_t sy,
                         std::uint32_t operation) = 0; // BitBlt565c5c0
    virtual std::int64_t get_dibits(Handle dc, Handle bitmap, std::uint32_t start,
                                    std::uint32_t count, std::vector<std::uint8_t> *pixels,
                                    BitmapInfo &, std::uint32_t usage) = 0; // 5727c68
    virtual Error last_native_error() = 0; // original Ka85a0u3OCV, may return nil for errno0
    virtual Error captured_error(std::uint32_t descriptor_rva) = 0;
    virtual std::vector<std::uint8_t>
    original_make_byte_slice(std::int64_t size) = 0; // panics as original on invalid size
    virtual RgbaImage original_new_rgba_rectangle(std::int64_t width, std::int64_t height) = 0;
    [[noreturn]] virtual void original_bounds_panic(std::uint64_t index, std::uint64_t length) = 0;
    virtual Error encode_original_jpeg(const RgbaImage &, std::int64_t quality,
                                       std::vector<std::uint8_t> &) = 0; // Ezd.MjNTIX @ef3dc0
    virtual ByteString base64_standard(const std::vector<std::uint8_t> &) = 0;
    virtual std::vector<ByteString> configured_window_classes() = 0; // 5732248/250
    virtual Handle original_find_window_by_class(
        const ByteString
            &) = 0; // n0Ay f34340: UTF16PtrFromString, ignored error, FindWindowW(class,NULL)
    virtual ByteString original_timed_string_scope(
        const std::function<ByteString()>
            &) = 0; // label/time.Now/deferred timing callback @U6.J4zzlapPd.func4
};
std::int64_t signed_width_difference(std::int32_t right, std::int32_t left) {
    const auto bits = std::uint32_t(right) - std::uint32_t(left);
    std::int32_t result;
    std::memcpy(&result, &bits, 4);
    return result; // original32-bit SUB, then MOVSXD
}
// @f34940: original delay only when an iconic window was restored.
bool restore_iconic_window(WindowCaptureContracts &r, WindowCaptureContracts::Handle window) {
    const bool iconic = r.is_iconic(window);
    if (iconic) {
        r.show_window(window, 9);
        r.sleep_nanoseconds(150000000);
    }
    return iconic;
}
// @f34a00. Do not collapse these fallbacks into one call.
bool try_print_window(WindowCaptureContracts &r, WindowCaptureContracts::Handle window,
                      WindowCaptureContracts::Handle memory_dc) {
    if (r.print_window(window, memory_dc, 3))
        return true;
    if (r.print_window(window, memory_dc, 2))
        return true;
    return r.print_window(window, memory_dc, 1);
}
// @f34b60: first query updates bitmap-info, then request height scan lines.
bool read_bitmap_pixels(WindowCaptureContracts &r, WindowCaptureContracts::Handle memory_dc,
                        WindowCaptureContracts::Handle bitmap, std::int64_t height,
                        std::vector<std::uint8_t> &pixels,
                        WindowCaptureContracts::BitmapInfo &info) {
    (void)r.get_dibits(memory_dc, bitmap, 0, 0, nullptr, info, 0);
    if (pixels.empty())
        r.original_bounds_panic(0, 0);
    return r.get_dibits(memory_dc, bitmap, 0, static_cast<std::uint32_t>(height), &pixels, info,
                        0) != 0;
}
// The original only considers B/G/R; alpha never makes a black image nonblack.
bool has_visible_rgb(WindowCaptureContracts &r, const std::vector<std::uint8_t> &pixels) {
    for (std::uint64_t at = 0; at < pixels.size(); at += 4)
        for (std::uint64_t channel = 0; channel < 3; ++channel) {
            if (at + channel >= pixels.size())
                r.original_bounds_panic(at + channel, pixels.size());
            if (pixels[at + channel] != 0)
                return true;
        }
    return false;
}
// @f34d00: bottom-up BGRA ->top-down RGBA, preserving the fourth byte.
RgbaImage bitmap_to_rgba(WindowCaptureContracts &r, const std::vector<std::uint8_t> &input,
                         std::int64_t width, std::int64_t height) {
    auto image = r.original_new_rgba_rectangle(width, height);
    for (std::int64_t y = 0; y < height; ++y)
        for (std::int64_t x = 0; x < width; ++x) {
            const auto source = (std::uint64_t(x) + (std::uint64_t(height) - std::uint64_t(y) - 1) *
                                                        std::uint64_t(width)) *
                                4;
            const auto destination =
                (std::uint64_t(x) + std::uint64_t(y) * std::uint64_t(width)) * 4;
            const std::array<std::uint64_t, 4> order = {2, 1, 0, 3};
            for (std::uint64_t channel = 0; channel < 4; ++channel) {
                if (source + order[channel] >= input.size())
                    r.original_bounds_panic(source + order[channel], input.size());
                if (destination + channel >= image.pixels.size())
                    r.original_bounds_panic(destination + channel, image.pixels.size());
                image.pixels[destination + channel] = input[source + order[channel]];
            }
        }
    return image;
}
// @f34f00. Native primitives are explicit Windows provider contracts; the application
// selection/capture flow is mapped here. This source was never run.
CaptureResult capture_window(WindowCaptureContracts &r, WindowCaptureContracts::Handle window) {
    return r.with_original_go_defers(
        [&](WindowCaptureContracts::DeferSink &defers) -> CaptureResult {
            if (!r.is_visible(window))
                return {{}, r.captured_error(0x3e2b5a8)};
            if (restore_iconic_window(r, window))
                defers.add([&r, window] { r.show_window(window, 6); });
            WindowCaptureContracts::Rect rect;
            if (!r.get_client_rect(window, rect))
                return {{}, r.last_native_error()};
            const auto width = signed_width_difference(rect.right, rect.left);
            const auto height = signed_width_difference(rect.bottom, rect.top);
            if (width < 1 || height < 1)
                return {{}, r.captured_error(0x3e2b558)};
            const auto desktop_dc = r.get_dc(0);
            if (!desktop_dc)
                return {{}, r.last_native_error()};
            defers.add([&r, desktop_dc] { r.release_dc(0, desktop_dc); });
            const auto memory_dc = r.compatible_dc(desktop_dc);
            if (!memory_dc)
                return {{}, r.last_native_error()};
            defers.add([&r, memory_dc] { r.delete_dc(memory_dc); });
            const auto bitmap = r.compatible_bitmap(desktop_dc, width, height);
            if (!bitmap)
                return {{}, r.last_native_error()};
            defers.add([&r, bitmap] { r.delete_object(bitmap); });
            const auto previous = r.select_object(memory_dc, bitmap);
            if (previous)
                defers.add(
                    [&r, memory_dc, previous] { (void)r.select_object(memory_dc, previous); });
            const auto copy_window_dc = [&] {
                const auto window_dc = r.get_dc(window);
                if (window_dc) {
                    (void)r.bit_blt(memory_dc, 0, 0, width, height, window_dc, 0, 0, 0xcc0020);
                    r.release_dc(window, window_dc);
                }
                return window_dc != 0;
            };
            if (!try_print_window(r, window, memory_dc))
                (void)copy_window_dc();
            WindowCaptureContracts::BitmapInfo info;
            info.width = static_cast<std::int32_t>(width);
            info.height = static_cast<std::int32_t>(height);
            const auto size_bits = std::uint64_t(width) * std::uint64_t(height) * 4;
            std::int64_t size;
            std::memcpy(&size, &size_bits, 8);
            auto pixels = r.original_make_byte_slice(size);
            if (!read_bitmap_pixels(r, memory_dc, bitmap, height, pixels, info)) {
                const bool copied = copy_window_dc();
                if (!copied || !read_bitmap_pixels(r, memory_dc, bitmap, height, pixels, info))
                    return {{}, r.last_native_error()};
            }
            if (!has_visible_rgb(r, pixels)) {
                if (copy_window_dc())
                    (void)read_bitmap_pixels(r, memory_dc, bitmap, height, pixels, info);
                if (!has_visible_rgb(r, pixels))
                    return {{}, r.captured_error(0x3e2b598)};
            }
            const auto image = bitmap_to_rgba(r, pixels, width, height);
            std::vector<std::uint8_t> jpeg;
            const auto error = r.encode_original_jpeg(image, 90, jpeg);
            if (error)
                return {{}, error};
            return {"data:image/jpeg;base64," + r.base64_standard(jpeg), {}};
        });
}
// @f343a0: choose LONGEST successful nonempty data URI, retaining earlier on equal length.
ByteString collect_game_window_screenshot(WindowCaptureContracts &r) {
    return r.original_timed_string_scope([&] {
        ByteString longest;
        for (const auto &class_name : r.configured_window_classes()) {
            const auto window = r.original_find_window_by_class(class_name);
            if (!window)
                continue;
            const auto captured = capture_window(r, window);
            if (!captured.error && !captured.encoded.empty() &&
                captured.encoded.size() > longest.size())
                longest = captured.encoded;
        }
        return longest;
    });
}
} // namespace ocean::reconstructed::window_capture_review
