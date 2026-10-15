#include "../../common/review_contracts.hpp"
namespace ocean::reconstructed {
// Recovered: union every display rectangle, capture that area, PNG-encode it, and
// return base64 over the produced buffer prefix. Capture failure returns "Unknown";
// PNG failure returns empty and an invalid buffer offset follows the panic path.
struct Rectangle {
    GoInt min_x, min_y, max_x, max_y;
};
struct ImageRef {
    std::uint64_t original_pointer;
};
struct GoBuffer {
    std::vector<std::uint8_t> bytes;
    GoInt offset;
};
struct ScreenshotContracts {
    virtual GoInt display_count() = 0;                            // 0xee6d40
    virtual Rectangle display_bounds(GoInt index) = 0;            // 0xee6dc0
    virtual Rectangle union_rectangles(Rectangle, Rectangle) = 0; // image.Rectangle.Union
    virtual Result<ImageRef> capture_rectangle(GoInt x, GoInt y, GoInt width,
                                               GoInt height) = 0; // 0xee4340
    virtual GoError encode_png_default(GoBuffer &, ImageRef) = 0; // 0xe6f320; zeroed Encoder
    virtual ByteString base64_encode(const std::vector<std::uint8_t> &, GoInt offset) = 0;
    virtual void bounds_panic() = 0;
};
// Original UAy9caHUbZ.Hz2wOTt6l @0xf341c0.
// All display bounds are combined, including negative monitor coordinates.
// Capture and PNG encoding are contracts for recovered library bodies, not
// implementations that operate on this host. No source from this tree is run.
ByteString screenshot_provider(ScreenshotContracts &runtime) {
    Rectangle area{0, 0, 0, 0};
    const auto count = runtime.display_count();
    for (GoInt index = 0; index < count; ++index)
        area = runtime.union_rectangles(area, runtime.display_bounds(index));
    const auto image = runtime.capture_rectangle(area.min_x, area.min_y, area.max_x - area.min_x,
                                                 area.max_y - area.min_y);
    if (image.error.present())
        return "Unknown";
    GoBuffer output{{}, 0};
    if (runtime.encode_png_default(output, image.value).present())
        return {};
    if (output.offset < 0 || static_cast<GoUint>(output.offset) > output.bytes.size())
        runtime.bounds_panic();
    return runtime.base64_encode(output.bytes, output.offset);
}
} // namespace ocean::reconstructed
