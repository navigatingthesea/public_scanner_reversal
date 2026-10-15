#include "windows_evtx_reader.hpp"
#include <algorithm>
#include <array>
#include <cstring>

// Recovered behavior summary:
//   Input: Random-access EVTX file bytes.
//   Gate: Validates recovered file/chunk/event signatures and sizes, repairs only the captured
//         dirty-header state, and walks newest chunks first.
//   Output: Returns decoded BinaryXML events through the Runtime codec boundary.
//   Failure: I/O, bounds, header, and decode errors propagate as Error; optional debug
//            resynchronization is provider-controlled.

namespace ocean::reconstructed::checks::evtx {
namespace {
constexpr std::array<std::uint8_t,8> kFileSignature{'E','l','f','F','i','l','e',0};
constexpr std::array<std::uint8_t,8> kChunkSignature{'E','l','f','C','h','n','k',0};
constexpr std::array<std::uint8_t,4> kEventSignature{0x2a,0x2a,0,0};
constexpr std::uint32_t kChunkSize = 0x10000;
constexpr std::uint32_t kRawChunkHeaderSize = 0x80;

std::uint16_t u16(const std::uint8_t* p) { return std::uint16_t(p[0]) | (std::uint16_t(p[1]) << 8); }
std::uint32_t u32(const std::uint8_t* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
           (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
std::uint64_t u64(const std::uint8_t* p) { std::uint64_t v=0; for(unsigned i=0;i!=8;++i)v|=std::uint64_t(p[i])<<(i*8); return v; }

bool read_exact(RandomAccess& reader, std::uint64_t offset, std::uint8_t* output,
                std::size_t length, Error& error) {
    error = {};
    const auto count = reader.read_at(offset, output, length, error);
    if (count == length) return true;
    if (error.text.empty()) error = {"short EVTX read", count == 0};
    return false;
}

FileHeader parse_file_header(const std::array<std::uint8_t,128>& b) {
    FileHeader h;
    std::copy_n(b.begin(),8,h.signature.begin());
    h.first_chunk_number=u64(b.data()+8); h.last_chunk_number=u64(b.data()+16);
    h.next_record_identifier=u64(b.data()+24); h.header_size=u32(b.data()+32);
    h.minor_version=u16(b.data()+36); h.major_version=u16(b.data()+38);
    h.header_block_size=u16(b.data()+40); h.chunk_count=u16(b.data()+42);
    std::copy_n(b.begin()+44,76,h.reserved.begin());
    h.flags=u32(b.data()+120); h.checksum=u32(b.data()+124);
    return h;
}

ChunkHeader parse_chunk_header(const Bytes& b) {
    ChunkHeader h;
    std::copy_n(b.begin(),8,h.signature.begin());
    h.first_event_record_number=static_cast<std::int64_t>(u64(b.data()+8));
    h.last_event_record_number=static_cast<std::int64_t>(u64(b.data()+16));
    h.first_event_record_identifier=static_cast<std::int64_t>(u64(b.data()+24));
    h.last_event_record_identifier=static_cast<std::int64_t>(u64(b.data()+32));
    h.header_size=static_cast<std::int32_t>(u32(b.data()+40));
    h.last_event_data_offset=static_cast<std::int32_t>(u32(b.data()+44));
    h.free_space_offset=static_cast<std::int32_t>(u32(b.data()+48));
    h.events_checksum=u32(b.data()+52);
    return h;
}

EventRecordHeader parse_event_header(const Bytes& b, std::int32_t offset) {
    EventRecordHeader h;
    const auto* p=b.data()+offset; std::copy_n(p,4,h.signature.begin());
    h.size=static_cast<std::int32_t>(u32(p+4));
    h.record_identifier=static_cast<std::int64_t>(u64(p+8));
    h.written_filetime=u64(p+16); return h;
}

bool valid_event_header(const EventRecordHeader& h, Error& error) {
    // EVWteO.(*KalxdCzas).Validate @0x1102120 performs exactly these three gates.
    if (h.signature != kEventSignature) { error={"invalid EVTX event signature",false}; return false; }
    if (h.size > 0xffff) { error={"EVTX event exceeds chunk size",false}; return false; }
    if (h.size <= 23) { error={"EVTX event is shorter than its 24-byte header",false}; return false; }
    return true;
}

std::uint16_t count_chunk_signatures(RandomAccess& reader, Error& error) {
    // Repair uses a 4096-byte buffered scanner and counts literal ElfChnk\0 occurrences.
    const auto length=reader.size(error); if(!error.text.empty()) return 0;
    constexpr std::size_t block=4096; Bytes carry; std::uint32_t count=0;
    for(std::uint64_t at=0;at<length;at+=block){
        Bytes data(std::min<std::uint64_t>(block,length-at)); Error read_error;
        const auto got=reader.read_at(at,data.data(),data.size(),read_error); data.resize(got);
        carry.insert(carry.end(),data.begin(),data.end());
        for(std::size_t i=0;i+8<=carry.size();++i) if(std::equal(kChunkSignature.begin(),kChunkSignature.end(),carry.begin()+i)) ++count;
        if(carry.size()>7) carry.erase(carry.begin(),carry.end()-7);
        if(!read_error.text.empty()&&!read_error.eof){error=read_error;return 0;}
    }
    return static_cast<std::uint16_t>(count);
}

bool repair_dirty_header(File& file, Error& error) {
    const auto count=count_chunk_signatures(*file.reader,error); if(!error.text.empty()) return false;
    if(count<file.header.chunk_count){error={"EVTX repair found fewer chunks than the header declares",false};return false;}
    file.header.chunk_count=count;
    file.header.last_chunk_number=static_cast<std::uint16_t>(count-1); // original writes low uint32
    file.header.flags=0;
    return true;
}

struct RawChunk {
    std::int64_t absolute_offset{};
    ChunkHeader header{};
};

std::optional<RawChunk> fetch_raw_chunk(File& file,std::int64_t offset,Error& error){
    Bytes raw(kRawChunkHeaderSize);
    if(!read_exact(*file.reader,offset,raw.data(),raw.size(),error)) return std::nullopt;
    return RawChunk{offset,parse_chunk_header(raw)};
}

struct ParsedChunk {
    RawChunk raw;
    Bytes bytes;
    std::map<std::uint32_t,Text> strings;
    std::map<std::uint32_t,Bytes> templates;
    std::vector<std::int32_t> event_offsets;
};

std::optional<ParsedChunk> fetch_chunk(File& file,const RawChunk& raw,Error& error){
    ParsedChunk c; c.raw=raw; c.bytes.resize(kChunkSize);
    if(!read_exact(*file.reader,raw.absolute_offset,c.bytes.data(),c.bytes.size(),error)) return std::nullopt;
    c.raw.header=parse_chunk_header(c.bytes);
    std::uint32_t cursor=static_cast<std::uint32_t>(c.raw.header.header_size);

    // ParseStringTable reads exactly 64 little-endian offsets (0..0xfc by four).
    for(unsigned i=0;i!=64;++i,cursor+=4){
        const auto offset=u32(c.bytes.data()+cursor); if(!offset) continue;
        Text value; Error local;
        if(file.runtime->decode_name_string(c.bytes,offset,value,local)) c.strings[offset]=std::move(value);
        else if(!file.runtime->debug_resynchronize_invalid_records()){error=local;return std::nullopt;}
    }
    // ParseTemplateTable reads exactly 32 offsets (0..0x7c by four), restoring table position after each body.
    for(unsigned i=0;i!=32;++i,cursor+=4){
        const auto offset=u32(c.bytes.data()+cursor); if(!offset) continue;
        Bytes value; Error local;
        if(file.runtime->decode_template(c.bytes,offset,value,local)) c.templates[offset]=std::move(value);
        else { error=local; return std::nullopt; }
    }

    // The first candidate begins immediately after the two tables, normally at chunk offset 0x200.
    std::int32_t event_offset=static_cast<std::int32_t>(cursor);
    c.event_offsets.push_back(event_offset);
    while(event_offset<=c.raw.header.last_event_data_offset){
        if(event_offset<0 || std::size_t(event_offset)+24>c.bytes.size()){
            error={"EVTX event offset leaves the chunk",false};
            return std::nullopt;
        }
        const auto h=parse_event_header(c.bytes,event_offset); Error validation;
        if(valid_event_header(h,validation)){
            event_offset+=h.size; c.event_offsets.push_back(event_offset);
        }else if(file.runtime->debug_resynchronize_invalid_records()){
            ++event_offset;
        }else{error=validation;return std::nullopt;}
    }
    // The original appends the first offset before validation and the next offset after every valid
    // record. ParseEvent rejects offsets after last_event_data_offset, so the final sentinel is harmless.
    return c;
}
}

// EVWteO.FTCsDJwXHK @0x1103e60 -> FaQAXG -> ParseFileHeader -> Verify/Repair.
std::optional<File> open(Runtime& runtime,const Text& path,Error& error){
    RandomAccess* reader=nullptr; if(!runtime.open_read_only(path,reader,error)) return std::nullopt;
    File file{{},reader,&runtime}; std::array<std::uint8_t,128> raw{};
    if(!read_exact(*reader,0,raw.data(),raw.size(),error)){runtime.close(*reader);return std::nullopt;}
    file.header=parse_file_header(raw);
    if(file.header.signature!=kFileSignature){error={"invalid EVTX file signature",false};runtime.close(*reader);return std::nullopt;}
    if(file.header.flags==1&&!repair_dirty_header(file,error)){runtime.close(*reader);return std::nullopt;}
    return file;
}

void close(File& file){if(file.reader){file.runtime->close(*file.reader);file.reader=nullptr;}}

std::vector<DecodedEvent> events(File& file,Error& error){
    std::vector<RawChunk> raw_chunks;
    for(std::uint32_t index=0;index<file.header.chunk_count;++index){
        const auto offset=std::int64_t(file.header.header_block_size)+std::int64_t(index)*kChunkSize;
        Error local; auto raw=fetch_raw_chunk(file,offset,local);
        if(raw) raw_chunks.push_back(*raw);
        else if(!local.eof){error=local;return {};}
    }
    // Chunks() inserts by first_event_record_number then consumes ReversedIter: newest chunk first.
    std::sort(raw_chunks.begin(),raw_chunks.end(),
        [](const RawChunk& a,const RawChunk& b){
            return a.header.first_event_record_number>
                   b.header.first_event_record_number;
        });
    std::vector<DecodedEvent> output;
    for(const auto& raw:raw_chunks){
        Error local; auto chunk=fetch_chunk(file,raw,local);
        if(!chunk){if(local.eof)continue;error=local;return {};}
        // A71EWz.Events walks the stored offsets forward inside each (newest-first) chunk.
        for(const auto offset:chunk->event_offsets){
            if(offset>chunk->raw.header.last_event_data_offset) continue;
            DecodedEvent event; event.chunk_offset=raw.absolute_offset; event.event_offset=offset;
            event.header=parse_event_header(chunk->bytes,offset);
            if(!file.runtime->decode_event_binary_xml(chunk->bytes,offset,chunk->strings,chunk->templates,event,local)) continue;
            output.push_back(std::move(event));
        }
    }
    return output;
}
}
