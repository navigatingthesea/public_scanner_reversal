#include "../session/session_types.hpp"
#include <set>
// Recovered behavior summary:
//   Input: The primary collected curl dependency list, with the prefetch collector used only when
//          that list is empty.
//   Gate: Drops empty paths and exact-byte duplicates.
//   Output: Emits one CURL report and one structured row per retained path.
//   Failure: A nonempty primary list containing only unusable entries still suppresses fallback.

namespace ocean::reconstructed::shared_curl_root_flow {
struct Contracts {
    virtual std::vector<ByteString> reviewed_curl_collected_dependencies()=0;
    virtual std::vector<ByteString> original_prefetch_fallback_after_baseline()=0;
    virtual void append_original_report(const ByteString&)=0;
    virtual void append_structured_collection_row(const std::vector<ByteString>&)=0;
};
void run(Contracts& runtime) { //BtZw@125e360
    auto paths=runtime.reviewed_curl_collected_dependencies();
    if(paths.empty()) paths=runtime.original_prefetch_fallback_after_baseline();
    std::set<ByteString> seen;
    for(const auto& path:paths) {
        if(path.empty() || !seen.insert(path).second) continue;
        runtime.append_original_report("Generic Bypass Method (CURL):::Boot instance:::Curl.exe directly modified a file");
        runtime.append_structured_collection_row({"Curl","Prefetch curl.exe files accessed",path});
    }
}
// Original no union between providers. A nonempty first list containingONLYempty
// strings still suppresses fallback, then yields no report. Dedup exactbytes before
// report, first occurrence order; case variants can differ.4 original listfixtures
// returned. Prefetch referenced-file access does not independently prove modified
// contents; wording is original scanner's heuristic attribution. Fallbackrawparser/
// Timestamp fallback and collected-input production are mapped in curl_prefetch_fallback.cpp and curl_name_predicates.cpp.
// VM-only readable C++ never compiled/run.
}
