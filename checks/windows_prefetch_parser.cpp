#include "windows_prefetch_parser.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>

// Recovered behavior summary:
//   Input: Random-access Windows Prefetch bytes, including optional MAM-compressed input.
//   Gate: Validates SCCA/version layouts, extracts the executable, hash, run times/count, and
//         referenced filenames with recovered offsets.
//   Output: Returns one PrefetchRecord matching the original 144-byte wrapper projection.
//   Failure: Open/read/decompression/layout failures return PrefetchError/nullopt; unknown versions
//            retain the recovered fallback layout.

namespace ocean::reconstructed::checks {
namespace {

constexpr std::uint32_t kCompressedMagic = 0x044d414d; // bytes "MAM\x04"
constexpr std::uint32_t kSccaMagic = 0x41434353;       // bytes "SCCA"

struct Reader {
    const Bytes* memory{};
    PrefetchRandomAccess* file{};

    std::size_t read(std::uint64_t offset, std::uint8_t* out, std::size_t size,
                     bool& eof, PrefetchError& error) const {
        eof = false;
        if (memory) {
            if (offset >= memory->size()) { eof = true; return 0; }
            const auto available = memory->size() - static_cast<std::size_t>(offset);
            const auto count = std::min(size, available);
            std::memcpy(out, memory->data() + offset, count);
            eof = count != size;
            return count;
        }
        return file->read_at(offset, out, size, eof, error);
    }
};

std::uint32_t read_u32(const Reader& reader, std::uint64_t offset) {
    std::array<std::uint8_t, 4> b{}; bool eof = false; PrefetchError ignored;
    if (reader.read(offset, b.data(), b.size(), eof, ignored) != b.size()) return 0;
    return std::uint32_t(b[0]) | (std::uint32_t(b[1]) << 8) |
           (std::uint32_t(b[2]) << 16) | (std::uint32_t(b[3]) << 24);
}

std::uint64_t read_u64(const Reader& reader, std::uint64_t offset) {
    std::array<std::uint8_t, 8> b{}; bool eof = false; PrefetchError ignored;
    if (reader.read(offset, b.data(), b.size(), eof, ignored) != b.size()) return 0;
    std::uint64_t value = 0;
    for (unsigned i = 0; i != 8; ++i) value |= std::uint64_t(b[i]) << (i * 8);
    return value;
}

ByteString decode_utf16le(const Reader& reader, std::uint64_t offset, std::size_t bytes) {
    Bytes raw(bytes); bool eof = false; PrefetchError ignored;
    const auto read = reader.read(offset, raw.data(), raw.size(), eof, ignored);
    raw.resize(read - (read & 1));
    std::size_t first = 0;
    if (raw.size() >= 2 && raw[0] == 0xff && raw[1] == 0xfe) first = 2;
    else if (raw.size() >= 2 && raw[0] == 0xfe && raw[1] == 0xff) first = 2;
    ByteString result;
    for (std::size_t i = first; i + 1 < raw.size(); i += 2) {
        const std::uint16_t word = std::uint16_t(raw[i]) | (std::uint16_t(raw[i + 1]) << 8);
        if (!word) break;
        // Readable reconstruction of Go's UTF-16 conversion. Surrogate-pair emission is
        // represented explicitly even though Prefetch executable/path names are normally BMP.
        std::uint32_t cp = word;
        if (word >= 0xd800 && word <= 0xdbff && i + 3 < raw.size()) {
            const auto low = std::uint16_t(raw[i + 2]) | (std::uint16_t(raw[i + 3]) << 8);
            if (low >= 0xdc00 && low <= 0xdfff) {
                cp = 0x10000 + ((word - 0xd800) << 10) + (low - 0xdc00); i += 2;
            }
        }
        if (cp <= 0x7f) result.push_back(char(cp));
        else if (cp <= 0x7ff) { result.push_back(char(0xc0 | (cp >> 6))); result.push_back(char(0x80 | (cp & 0x3f))); }
        else if (cp <= 0xffff) {
            result.push_back(char(0xe0 | (cp >> 12)));
            result.push_back(char(0x80 | ((cp >> 6) & 0x3f)));
            result.push_back(char(0x80 | (cp & 0x3f)));
        }
        else {
            result.push_back(char(0xf0 | (cp >> 18)));
            result.push_back(char(0x80 | ((cp >> 12) & 0x3f)));
            result.push_back(char(0x80 | ((cp >> 6) & 0x3f)));
            result.push_back(char(0x80 | (cp & 0x3f)));
        }
    }
    return result;
}

ByteString read_executable_name(const Reader& reader) {
    // X6nvS2TD2b4 reads at most 0x400 bytes from offset 0x10, finds the first UTF-16 NUL,
    // rounds an odd byte position upward, and decodes that prefix.
    std::array<std::uint8_t, 0x400> raw{}; bool eof = false; PrefetchError ignored;
    const auto count = reader.read(0x10, raw.data(), raw.size(), eof, ignored);
    std::size_t end = 0;
    while (end + 1 < count && (raw[end] != 0 || raw[end + 1] != 0)) end += 2;
    Bytes local(raw.begin(), raw.begin() + std::min(end, count));
    Reader memory{&local, nullptr};
    return decode_utf16le(memory, 0, local.size());
}

enum class Version : std::uint32_t {
    WinXP = 17,
    Vista = 23,
    Win81 = 26,
    Win10 = 30,
    Win11 = 31
};

ByteString version_name(std::uint32_t value) {
    switch (static_cast<Version>(value)) {
        case Version::WinXP: return "WinXP";
        case Version::Vista: return "Vista";
        case Version::Win81: return "Win8.1";
        case Version::Win10: return "Win10";
        case Version::Win11: return "Win11";
    }
    return "Unknown";
}

RecoveredTime decode_filetime(std::uint64_t value) {
    // Equivalent readable form of original WinFileTime arithmetic at 0x6574c0.
    constexpr std::uint64_t kTicksPerSecond = 10'000'000;
    constexpr std::int64_t kUnixEpochDifference = 11'644'473'600;
    const auto seconds = static_cast<std::int64_t>(value / kTicksPerSecond) - kUnixEpochDifference;
    return {seconds, static_cast<std::uint32_t>((value % kTicksPerSecond) * 100)};
}

struct FilenameLayout {
    std::uint32_t metrics_offset_at;
    std::uint32_t metrics_count_at;
    std::uint32_t strings_offset_at;
    std::uint32_t metric_name_offset_at;
    std::uint32_t metric_name_length_at;
    std::uint32_t metric_stride;
};

std::vector<ByteString> read_filenames(const Reader& reader, std::uint64_t file_info,
                                       const FilenameLayout& layout) {
    std::vector<ByteString> result;
    const auto strings = file_info + read_u32(reader, file_info + layout.strings_offset_at);
    auto metric = file_info + read_u32(reader, file_info + layout.metrics_offset_at);
    const auto count = read_u32(reader, file_info + layout.metrics_count_at);
    result.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i, metric += layout.metric_stride) {
        const auto relative = read_u32(reader, metric + layout.metric_name_offset_at);
        const auto characters = read_u32(reader, metric + layout.metric_name_length_at);
        result.push_back(decode_utf16le(reader, strings + relative, std::size_t(characters) * 2));
    }
    return result;
}

struct ParsedPrefetch {
    ByteString executable;
    std::uint32_t file_size{};
    ByteString hash;
    ByteString version;
    std::vector<RecoveredTime> last_run_times;
    std::vector<ByteString> files_accessed;
    std::uint32_t run_count{};
};

std::optional<ParsedPrefetch> parse_reader(PrefetchRuntime& runtime, Reader reader,
                                           PrefetchError& error) {
    Bytes decompressed;
    if (read_u32(reader, 0) == kCompressedMagic) {
        const auto output_size = read_u32(reader, 4);
        Bytes compressed(output_size); bool eof = false;
        const auto count = reader.read(8, compressed.data(), compressed.size(), eof, error);
        // The original accepts io.EOF here and passes the actual byte count to the decoder.
        if (!error.text.empty() && !eof) return std::nullopt;
        compressed.resize(count);
        if (!runtime.decompress_xpress_huffman(compressed, output_size, decompressed, error)) return std::nullopt;
        reader = Reader{&decompressed, nullptr};
    }

    if (read_u32(reader, 4) != kSccaMagic) {
        error.text = "invalid Prefetch signature"; // original returns its decoded signature error
        return std::nullopt;
    }

    ParsedPrefetch parsed;
    parsed.executable = read_executable_name(reader);
    parsed.file_size = read_u32(reader, 0x0c);
    char hash[11]{};
    std::snprintf(hash, sizeof(hash), "0x%08X", read_u32(reader, 0x4c));
    parsed.hash = hash;
    const auto raw_version = read_u32(reader, 0);
    parsed.version = version_name(raw_version);
    constexpr std::uint64_t file_info = 0x54;

    if (raw_version == static_cast<std::uint32_t>(Version::Vista)) {
        parsed.last_run_times.push_back(decode_filetime(read_u64(reader, file_info + 0x2c)));
        parsed.files_accessed = read_filenames(reader, file_info, {0x00, 0x04, 0x10, 0x0c, 0x10, 0x20});
        parsed.run_count = read_u32(reader, file_info + 0x44);
        return parsed;
    }
    if (raw_version == static_cast<std::uint32_t>(Version::WinXP)) {
        parsed.last_run_times.push_back(decode_filetime(read_u64(reader, file_info + 0x24)));
        parsed.files_accessed = read_filenames(reader, file_info, {0x00, 0x04, 0x10, 0x08, 0x0c, 0x14});
        parsed.run_count = read_u32(reader, file_info + 0x3c);
        return parsed;
    }

    // Win8.1, Win10, Win11, and the original's Unknown version all use this branch.
    for (std::uint32_t i = 0; i != 8; ++i) {
        const auto time = decode_filetime(read_u64(reader, file_info + 0x2c + i * 8));
        if (time.unix_seconds <= runtime.now_unix_seconds()) parsed.last_run_times.push_back(time);
    }
    parsed.files_accessed = read_filenames(reader, file_info, {0x00, 0x04, 0x10, 0x0c, 0x10, 0x20});
    parsed.run_count = read_u32(reader, file_info + 0x7c);
    if (!parsed.run_count) parsed.run_count = read_u32(reader, file_info + 0x74);
    return parsed;
}
}

// GPxy7u3aVEO.DCZmQW01a6t6 @0x65c880 wrapping abmiMFN.XCiwPqPjn @0x6586c0.
std::optional<PrefetchRecord> parse_prefetch_file(
    PrefetchRuntime& runtime, const ByteString& path, PrefetchError& error) {
    PrefetchRandomAccess* file = nullptr;
    if (!runtime.open_read_only(path, file, error)) return std::nullopt;
    struct Close { PrefetchRuntime& r; PrefetchRandomAccess* f; ~Close(){ if(f) r.close(*f); } } close{runtime, file};
    auto parsed = parse_reader(runtime, Reader{nullptr, file}, error);
    if (!parsed) return std::nullopt;
    PrefetchRecord result;
    result.file_name = path;
    result.executable_name = parsed->executable;
    result.command_line = {}; // confirmed zeroed by the 144-byte wrapper copy
    result.file_size = parsed->file_size;
    result.hash = parsed->hash;
    result.version = parsed->version;
    result.last_run_times = std::move(parsed->last_run_times);
    result.files_accessed = std::move(parsed->files_accessed);
    result.run_count = parsed->run_count;
    return result;
}
}
