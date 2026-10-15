#include "../../session/session_types.hpp"
#include <algorithm>
#include <map>
namespace ocean::reconstructed::minecraft_artifact_path_gates {
struct Artifact {
    bool flag_at_9=false; // any empty/temporary/missing candidate in artifact profile
    std::map<ByteString,bool> domains_at_24;
};
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
    virtual bool reviewed_exact_mods_component(const ByteString&)=0;
    virtual bool reviewed_secondary_sensitive_domains(
        const std::map<ByteString,bool>&)=0;
};
// Recovered: gLGXrn41W @ 0x1e6c680..0x1e6dde0. A candidate passes when it has
// a profile whose unbacked flag is clear and its lowercased, slash-normalized
// path either contains an exact "mods" component or one listed client/library
// prefix. This is a syntactic path/metadata gate.
bool candidate_in_known_path(Contracts& runtime,const ByteString& candidate,
                             const Artifact* artifact) {
    if(!artifact || artifact->flag_at_9 || candidate.empty()) return false;
    auto path=candidate;
    std::replace(path.begin(),path.end(),'/','\\');
    path=runtime.original_unicode_lowercase(path);
    if(runtime.reviewed_exact_mods_component(path)) return true;
    for(const ByteString prefix:{"\\.minecraft\\libraries\\",
        "\\.minecraft\\versions\\","\\.fabric\\processedmods\\",
        "\\modrinthapp\\profiles\\","\\.lunarclient\\",
        "\\badlion client\\","\\feather\\","\\labymod\\"})
        if(path.find(prefix)!=ByteString::npos) return true;
    return false;
}
// Recovered: dKzuOLh8ifx2 @ 0x1e6c600. A secondary artifact is sensitive when it
// is nonempty, has a profile, does not pass the known-path gate, and its handler
// domains satisfy the secondary-sensitive predicate. Metadata flag 9 makes the
// known-path gate false; it does not directly make sensitivity false.
bool secondary_artifact_sensitive(Contracts& runtime,const ByteString& candidate,
                                  const Artifact* artifact) {
    if(candidate.empty() || !artifact) return false;
    if(candidate_in_known_path(runtime,candidate,artifact)) return false;
    return runtime.reviewed_secondary_sensitive_domains(artifact->domains_at_24);
}
// The exact mods-component predicate is reviewed separately: lower/split only
// slash/backslash, component equals mods, with no whitespace trimming.
// Interpretation: this gate does not establish file existence, signatures, JAR
// content, extension, provenance, or safety. Even an .exe path can pass.
//51 original returned cases:43 path boundaries and8 combined sensitivity.
// New source remains guest-only and has never been compiled or executed.
}

// Recovered: java_artifact_profiles.cpp produces flag 9 by OR-ing every
// empty/temporary/missing cluster-candidate flag for the exact artifact key.
// Map 24 contains correlated handler domains; map 16 additionally contains
// class/JAR-derived features.
