#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Recovered behavior summary:
//   Input: Typed file/decompression provider boundary and semantic PrefetchRecord.
//   Gate: The interface preserves ReaderAt-style short-read/EOF behavior and recovered output
//         fields.
//   Output: Declares parse_prefetch_file for check consumers.
//   Failure: Native file access and XPRESS-Huffman decompression remain provider responsibilities.

namespace ocean::reconstructed::checks {
using ByteString = std::string;
using Bytes = std::vector<std::uint8_t>;

struct RecoveredTime {
    std::int64_t unix_seconds{};
    std::uint32_t nanoseconds{};
};

struct PrefetchRecord {
    ByteString file_name;          // JSON "FileName"
    ByteString executable_name;    // JSON "ExecutableName"
    ByteString command_line;       // JSON "CommandLine"; original wrapper leaves it empty
    std::uint32_t file_size{};      // JSON "FileSize"
    ByteString hash;               // JSON "Hash", exactly 0x%08X
    ByteString version;            // WinXP, Vista, Win8.1, Win10, Win11, or Unknown
    std::vector<RecoveredTime> last_run_times;
    std::vector<ByteString> files_accessed;
    std::uint32_t run_count{};
};

struct PrefetchError {
    ByteString text;
};

struct PrefetchRandomAccess {
    virtual ~PrefetchRandomAccess() = default;
    // Mirrors Go io.ReaderAt: returns bytes read and an error flag; eof is distinguished.
    virtual std::size_t read_at(std::uint64_t offset, std::uint8_t* destination,
                                std::size_t requested, bool& eof, PrefetchError& error) = 0;
};

struct PrefetchRuntime {
    virtual ~PrefetchRuntime() = default;
    virtual bool open_read_only(const ByteString& path, PrefetchRandomAccess*& file,
                                PrefetchError& error) = 0;
    virtual void close(PrefetchRandomAccess& file) = 0;
    // The original tries the Windows decompression entry point first and falls back to
    // its bundled XPRESS-Huffman decoder when the entry point is absent or returns failure.
    virtual bool decompress_xpress_huffman(const Bytes& compressed, std::uint32_t output_size,
                                           Bytes& decompressed, PrefetchError& error) = 0;
    virtual std::int64_t now_unix_seconds() const = 0;
};

std::optional<PrefetchRecord> parse_prefetch_file(
    PrefetchRuntime& runtime, const ByteString& path, PrefetchError& error);
}
