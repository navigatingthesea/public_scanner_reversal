#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: EVTX file header flags and the reader chunk/event stream.
//   Gate: Requires ElfFile\0; only flags == 1 requests repair. The producer skips EOF chunk fetches
//         and forwards every decoded event.
//   Output: Returns header status and a capacity-one event channel.
//   Failure: Non-EOF chunk errors panic through the provider; channel close is deferred.

namespace ocean::reconstructed::shared_evtx_reader_flow {
enum class HeaderResult {
    Success,
    BadSignature,
    RepairRequired
};
HeaderResult verify_header(const ByteString& signature,std::uint32_t flags120) {
    if(signature!=ByteString("ElfFile\0",8)) return HeaderResult::BadSignature;
    return flags120==1 ? HeaderResult::RepairRequired : HeaderResult::Success;
}
// Original compares flags EXACT1, not bit0;3 accepted.7 original synthetic cases
// returned (valid0/1/2/3/4/UINT32MAX and badsig0). Captured sentinel globals
//572c630/638badSignature and572c640/648repair. Header wrapper compares BOTHerror
// interface type and payload equality beforeRepair; unrelatederrorspropagate.
struct Reader {
    std::uint64_t original_identity;
};
struct Chunk {
    std::uint64_t original_identity;
};
struct Event {
    std::uint64_t original_identity;
};
struct Fetch {
    Chunk chunk;
    bool error,is_original_eof;
};
struct Channel {
    std::uint64_t original_identity;
};
struct Contracts {
    virtual Channel make_event_channel_capacity_one()=0;
    virtual void spawn_original_event_producer(Reader,Channel)=0;
    virtual void defer_close_channel(Channel)=0;
    virtual bool next_original_chunk_id(Reader,std::uint64_t&)=0;
    virtual Fetch original_fetch_chunk(Reader,std::uint64_t)=0;
    virtual bool next_original_chunk_event(Chunk&,Event&)=0;
    virtual void send_event_blocking(Channel,const Event&)=0;
    virtual void panic_with_original_error()=0;
};
Channel events(Contracts& runtime,Reader reader) { //Events@1105a40
    const auto output=runtime.make_event_channel_capacity_one();
    runtime.spawn_original_event_producer(reader,output);return output;
}
void produce_events(Contracts& runtime,Reader reader,Channel output) { //func1@1105b20
    runtime.defer_close_channel(output);
    std::uint64_t id=0;
    while(runtime.next_original_chunk_id(reader,id)) {
        auto fetched=runtime.original_fetch_chunk(reader,id);
        if(fetched.error) {
            if(fetched.is_original_eof) continue;
            runtime.panic_with_original_error();return;
        }
        Event event{};
        while(runtime.next_original_chunk_event(fetched.chunk,event))
            runtime.send_event_blocking(output,event);
    }
}
// Static original producer: rangesChunkschannel; FetchChunknilerr=>rangeschunk.Events;
// exactEOFinterface565e340/348 skip; othererrpanic; deferredoutputclose onallpaths.
// Ordering per inputchunk/event streams retained, channelcapacity1, no cancellation
// branch seen. Producer panic has no local recovery in this body. This is a semantic
// STATIC mapping, not a dynamic goroutine/EVTX parse proof. Chunk/FileHeader parsing,
// File/header repair, chunk ordering, table scans, event offsets and close/error behavior are
// reconstructed in windows_evtx_reader.cpp; generic BinaryXML node decoding is the typed runtime
// boundary.
// No file reading/native APIs/goroutines/sample/C++ execution in analysis.
// VM-only readable C++ never compiled/run.
}
