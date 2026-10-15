#pragma once
#include "../session/session_types.hpp"

namespace ocean::reconstructed::gzip_payload_review {
struct ErrorWords {
    std::uint64_t type = 0;
    std::uint64_t data = 0;
    bool present() const { return type != 0; }
};
struct ByteSlice {
    std::vector<std::uint8_t> bytes;
    bool nil = true;
    GoInt capacity = 0;
};
struct ByteResult {
    ByteSlice value;
    ErrorWords error;
};
struct WriterResult {
    std::uint64_t writer = 0;
    ErrorWords error;
};
struct WriteResult {
    GoInt count = 0;
    ErrorWords error;
};
struct Buffer {
    std::vector<std::uint8_t> backing;
    GoInt capacity = 0;
    GoInt read_offset = 0;
    bool nil = true;
};

struct GzipContracts {
    virtual WriterResult original_new_gzip_writer(Buffer&, int level) = 0;
    virtual WriteResult original_gzip_write(std::uint64_t, const ByteSlice&) = 0;
    virtual ErrorWords original_gzip_close(std::uint64_t) = 0;
    [[noreturn]] virtual void original_buffer_slice_bounds_panic() = 0;
};

ByteResult compress_payload(GzipContracts&, const ByteSlice&);
}
