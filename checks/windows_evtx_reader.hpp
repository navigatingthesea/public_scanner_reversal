#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Recovered behavior summary:
//   Input: Typed random-access and BinaryXML codec boundaries for EVTX parsing.
//   Gate: The declarations preserve recovered header fields, offsets, and event ordering contracts.
//   Output: Exposes open, close, and events APIs plus decoded event records.
//   Failure: BinaryXML name/template/event decoding remains a Runtime dependency rather than
//            invented source.

namespace ocean::reconstructed::checks::evtx {
using Bytes = std::vector<std::uint8_t>;
using Text = std::string;

struct Error { Text text; bool eof{}; };

struct FileHeader {
    std::array<std::uint8_t,8> signature{};
    std::uint64_t first_chunk_number{};
    std::uint64_t last_chunk_number{};
    std::uint64_t next_record_identifier{};
    std::uint32_t header_size{};
    std::uint16_t minor_version{};
    std::uint16_t major_version{};
    std::uint16_t header_block_size{};
    std::uint16_t chunk_count{};
    std::array<std::uint8_t,76> reserved{};
    std::uint32_t flags{};
    std::uint32_t checksum{};
};

struct ChunkHeader {
    std::array<std::uint8_t,8> signature{};
    std::int64_t first_event_record_number{};
    std::int64_t last_event_record_number{};
    std::int64_t first_event_record_identifier{};
    std::int64_t last_event_record_identifier{};
    std::int32_t header_size{};
    std::int32_t last_event_data_offset{};
    std::int32_t free_space_offset{};
    std::uint32_t events_checksum{};
};

struct EventRecordHeader {
    std::array<std::uint8_t,4> signature{}; // 2a 2a 00 00
    std::int32_t size{};
    std::int64_t record_identifier{};
    std::uint64_t written_filetime{};
};

struct DecodedEvent {
    std::int64_t chunk_offset{};
    std::int32_t event_offset{};
    EventRecordHeader header{};
    // The BinaryXML library ultimately exposes a string-keyed event map. The application
    // uses helpers such as EventID(), TimeCreated(), Channel(), GetString(), and JSON/XML conversion.
    std::map<Text, Text> scalar_fields;
    Text rendered_xml;
};

struct RandomAccess {
    virtual ~RandomAccess() = default;
    virtual std::size_t read_at(std::uint64_t offset, std::uint8_t* output,
                                std::size_t length, Error& error) = 0;
    virtual std::uint64_t size(Error& error) = 0;
};

struct Runtime {
    virtual ~Runtime() = default;
    virtual bool open_read_only(const Text& path, RandomAccess*& file, Error& error) = 0;
    virtual void close(RandomAccess& file) = 0;
    virtual bool debug_resynchronize_invalid_records() const = 0;
    // These are the generic EVTX BinaryXML library bodies. Their table offsets and invocation
    // order are reconstructed in the caller; node/value decoding stays behind this typed boundary.
    virtual bool decode_name_string(const Bytes& chunk, std::uint32_t offset, Text& value, Error& error) = 0;
    virtual bool decode_template(const Bytes& chunk, std::uint32_t offset, Bytes& value, Error& error) = 0;
    virtual bool decode_event_binary_xml(const Bytes& chunk, std::int32_t event_offset,
                                         const std::map<std::uint32_t,Text>& strings,
                                         const std::map<std::uint32_t,Bytes>& templates,
                                         DecodedEvent& event, Error& error) = 0;
};

struct File {
    FileHeader header{};
    RandomAccess* reader{};
    Runtime* runtime{};
};

std::optional<File> open(Runtime& runtime, const Text& path, Error& error);
void close(File& file);
std::vector<DecodedEvent> events(File& file, Error& error);
}
