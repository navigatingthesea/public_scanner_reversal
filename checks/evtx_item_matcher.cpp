#include "../session/session_types.hpp"
#include <set>
// Recovered behavior summary:
//   Input: Caller-normalized event text and a rule term list.
//   Gate: Trims and lowercases each nonempty original term, then performs byte-substring matching
//         and exact normalized deduplication.
//   Output: Returns matched normalized terms in first-occurrence order.
//   Failure: Whitespace-only nonempty terms normalize to empty and therefore match every string,
//            preserving recovered behavior.

namespace ocean::reconstructed::shared_evtx_item_matcher {
struct Contracts {
    virtual ByteString original_unicode_trim_space(const ByteString&)=0;
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
};
std::vector<ByteString> match(Contracts& runtime,const ByteString& supplied_text,
                             const std::vector<ByteString>& terms) { //wlb@12a1820
    std::vector<ByteString> result;std::set<ByteString> seen;
    for(const auto& original:terms) {
        if(original.empty()) continue;
        const auto normalized=runtime.original_unicode_lowercase(runtime.original_unicode_trim_space(original));
        if(supplied_text.find(normalized)!=ByteString::npos && seen.insert(normalized).second)
            result.push_back(normalized);
    }
    return result;
}
// Text is NOT normalized inside this helper; caller zlI0nBM joins event fields with
// separator3 bytes and lowers the joined result before passing it. Return normalized
// terms, not event substrings. Byte-exact dedup, first occurrence order preserved.
// ORIGINAL nonempty whitespace-only term becomesempty and qualifies (Contains empty).
//10 original helper paths returned: inputcase/needlecase/trim/empty/dedup/ordering/
// embedded substring. Caller event XML/ID/time/provider rules are represented by the EVTX flow sources.
// VM-only readable C++ never compiled/run.
}
