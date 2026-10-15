#include "../../session/session_types.hpp"
#include <vector>
namespace ocean::reconstructed::minecraft_java_evidence_buffer {
using Bytes=std::vector<std::uint8_t>;
struct SharedBudget {
    virtual std::int64_t atomic_load()=0;
    virtual bool atomic_compare_exchange(std::int64_t expected,std::int64_t replacement)=0;
};
struct Buffer {Bytes bytes;bool full=false;SharedBudget* shared=nullptr;};
void append(Buffer& buffer,const Bytes& input) { //nzQt@1a41160
    if(input.empty() || buffer.full) return;
    constexpr std::int64_t maximum=0x4000000; // 64 MiB per buffer
    const auto available=maximum-static_cast<std::int64_t>(buffer.bytes.size());
    if(available<=8) {buffer.full=true;return;}
    auto reserved=static_cast<std::int64_t>(input.size())+8;
    if(reserved>available) {buffer.full=true;reserved=available;}
    if(buffer.shared) {
        for(;;) {
            const auto remaining=buffer.shared->atomic_load();
            if(remaining<9) {buffer.full=true;return;}
            const auto take=remaining<reserved ? remaining : reserved;
            if(remaining<reserved) buffer.full=true;
            if(buffer.shared->atomic_compare_exchange(remaining,remaining-take)) {reserved=take;break;}
        }
    }
    // Recovered: each accepted entry starts with eight zero bytes. The helper
    // stores no per-entry length.
    buffer.bytes.insert(buffer.bytes.end(),8,0);
    buffer.bytes.insert(buffer.bytes.end(),input.begin(),input.begin()+reserved-8);
}
// Recovered: no per-entry length, deduplication, or encoding normalization occurs.
// Once full is set, all future nonempty append calls are suppressed. Exact budget
// exhaustion on a whole entry leaves full=false until a later append discovers
// exhaustion. A CAS race can leave full set from a previous smaller budget even
// if a retry sees more room; the sticky original flag is retained.
//16 original-body fixtures verified empty/full gates,64MiB boundaries, shared
// budgets0/8/9..12/negative, zero separator and partial copying. CAS contention
// paths reviewed statically.
// Unresolved: concurrent CAS behavior was not replayed.
// Native/source never run.
}
