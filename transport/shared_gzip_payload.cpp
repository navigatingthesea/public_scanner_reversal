#include "shared_gzip_payload.hpp"

namespace ocean::reconstructed::gzip_payload_review {
// Eh22kL_@f24900
ByteResult compress_payload(GzipContracts& runtime, const ByteSlice& input) {
    Buffer output;
    const auto created = runtime.original_new_gzip_writer(output, 9);
    if (created.error.present()) return {{}, created.error};

    const auto written = runtime.original_gzip_write(created.writer, input);
    if (written.error.present()) {
        (void)runtime.original_gzip_close(created.writer);
        // Recovered: preserve the write error even if cleanup also fails.
        return {{}, written.error};
    }

    // Recovered: a short write with nil error is accepted; count is ignored.
    const auto close_error = runtime.original_gzip_close(created.writer);
    if (close_error.present()) return {{}, close_error};

    if (output.read_offset < 0 ||
        static_cast<GoUint>(output.read_offset) > output.backing.size())
        runtime.original_buffer_slice_bounds_panic();

    ByteSlice result;
    result.nil = output.nil;
    result.capacity = output.capacity - output.read_offset;
    result.bytes.assign(
        output.backing.begin() + output.read_offset,
        output.backing.end());
    return {result, {}};
}

// Input is an existing Go-like byte slice. Output is the unread bytes of a
// level-9 gzip buffer with its original nil/capacity metadata. Writer creation,
// Write, and Close errors stop in that order. A malformed buffer offset triggers
// the original bounds panic. Codec and bytes.Buffer mutation remain provider
// contracts. Nine control-flow fixtures and one panic path were checked using
// synthetic output bytes; no codec or reconstructed source was executed.
}
