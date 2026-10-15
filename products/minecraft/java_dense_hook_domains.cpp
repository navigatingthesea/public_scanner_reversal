#include "../../session/session_types.hpp"
#include <map>
namespace ocean::reconstructed::minecraft_hook_domains {
using HookDomains = std::map<ByteString, bool>;
bool has(const HookDomains* domains, const ByteString& key) {
    if (!domains) return false;
    const auto found = domains->find(key);
    return found != domains->end() && found->second;
}
// Recovered: rzcLzgo9eer, RVA 0x1e6dde0..0x1e6e020. A dense hook set requires
// the exact true-valued keys combat and network, plus movement or entity_render.
// No lowercasing, substring search, key counting, scoring, or I/O occurs here.
bool dense_cross_domain_hooks(const HookDomains* domains) {
    return has(domains, "combat") && has(domains, "network") &&
           (has(domains, "movement") || has(domains, "entity_render"));
}
// Recovered: in g2, DENSE_CROSS_DOMAIN_HOOKS (82) additionally requires the Wilson
// confidence flag and an empty, temporary, or missing artifact. Domain-map
// population is a separate producer; this helper does not inspect a process,
// Minecraft, memory, files, or network itself. 16 truth-table combinations,
// nil/empty maps and two discovery cases returned under guarded interpretation.
// Generated only in the VM. Never compiled or executed as C++.
}

namespace ocean::reconstructed::minecraft_hook_domains {
// Recovered: fzNYW1F6wx @ 0x1e6c240. Secondary sensitivity is broader than the
// dense predicate. It accepts network with movement/combat/entity_render, or
// combat with entity_render. It emits no rule by itself.
// Twenty original cases covered all 16 exact-map truth combinations.
bool secondary_sensitive_domains(const HookDomains* domains) {
    const bool network=has(domains,"network"),combat=has(domains,"combat");
    return (network && (has(domains,"movement") || combat ||
                       has(domains,"entity_render"))) ||
           (combat && has(domains,"entity_render"));
}
}
