#include "../../session/session_types.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <vector>
namespace ocean::reconstructed::minecraft_linked_reference_examples {
struct Reference72 {
    std::uint64_t word_at_0=0; // not read by this helper
    ByteString kind_at_8;     // not tested by this helper
    ByteString owner_at_24;
    ByteString member_at_40;
    ByteString descriptor_at_56;
};
struct Class320 {
    ByteString name_at_0;
    std::vector<Reference72> references_at_232;
};
struct Cluster {
    ByteString namespace_at_24;
    std::map<ByteString,bool> simple_names_at_40;
};
ByteString normalize_owner(ByteString value) {
    std::replace(value.begin(),value.end(),'/','.');
    return value; // no lowercasing, trimming, slash collapse or path I/O
}
ByteString namespace_of(const ByteString& value) {
    const auto dot=value.rfind('.');
    return dot==ByteString::npos ? ByteString{} : value.substr(0,dot);
}
ByteString simple_name(const ByteString& value) {
    const auto dot=value.rfind('.');
    return dot==ByteString::npos ? value : value.substr(dot+1);
}
std::vector<ByteString> examples(const Class320& host,const Cluster& target) {
    // Recovered: gVL6j7hA, RVA 0x1ea15c0..0x1ea2500. The 320-byte class
    // record is a Go value argument on the stack; AX carries the cluster.
    std::set<ByteString> unique;
    for(const auto& reference:host.references_at_232) {
        const auto owner=normalize_owner(reference.owner_at_24);
        // Recovered gates: ignore a self-reference, require an exact namespace
        // match after slash-to-dot owner normalization, and require the target's
        // exact simple-name map entry to exist with value true.
        if(owner==host.name_at_0) continue;
        if(namespace_of(owner)!=target.namespace_at_24) continue;
        const auto found=target.simple_names_at_40.find(simple_name(owner));
        if(found==target.simple_names_at_40.end() || !found->second) continue;
        unique.insert(owner+"::"+reference.member_at_40+reference.descriptor_at_56);
    }
    // Recovered: sort the complete deduplicated list, then truncate to three.
    // Concatenation has no separator between member and descriptor: distinct
    // field pairs can intentionally collapse into identical example strings.
    std::vector<ByteString> result(unique.begin(),unique.end());
    if(result.size()>3) result.resize(3);
    return result;
}
//19 original helper fixtures returned, covering exact owner/namespace/name
// membership, current-host exclusion, slash normalization, ordinary methods,
// type/index words ignored, duplicates, concatenation collision and sorted cap.
// Member names need not contain attack/packet/movement. Kind is not validated.
// Recovered: the SDK reports these as CP_BEHAVIOR_HINTS. That output label
// establishes the consumer's role.
// Nonempty examples also allow handler correlation when flag64 is false.
// Unresolved: raw constant-pool reference production remains a separate unit.
// Generated inside VM; never compiled or executed as C++.
}
