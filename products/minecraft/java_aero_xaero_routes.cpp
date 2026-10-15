#include "../../session/session_types.hpp"
#include <array>
#include <set>
#include <string_view>
#include <vector>

namespace ocean::reconstructed::minecraft_aero_xaero_routes {
struct Rule {
    std::string_view id;
    std::int64_t score;
};

// Recovered: gKUdZHIZpX.init populates a map[string]struct{} at image RVA
// 0x5729020 with these 43 identifiers. Exact RIP-relative references to this
// global were found only in that initializer. References to 0x5729030,
// 0x5729058 and 0x5729060 address neighboring globals instead.
//
// Unresolved: no runtime reader of this table exists in the preserved corpus.
// Its presence establishes initialized data, not an active Xaero check.
static constexpr std::array<std::string_view, 43> kCapturedModIds{{
 "appleskin","architectury","better-fps","c2me","cloth-config","continuity",
 "dynamiclights","emi","entityculling","fabric-api","ferritecore","immediatelyfast",
 "indium","inventoryprofiles","iris","itemscroller","jade","jei","journeymap",
 "krypton","lambdynamiclights","lazydfu","litematica","lithium","malilib",
 "memoryleakfix","minihud","modmenu","noisium","optifabric","optifine","phosphor",
 "rei","replaymod","roughly","smoothboot","sodium","starlight","tweakeroo","vmp",
 "worldedit","wthit","xaero"
}};
constexpr bool kHasProvedRuntimeConsumer = false;

struct GenericInputs {
    ByteString lowered_namespace;
    std::size_t explicit_module_names = 0;
    std::size_t gui_component_names = 0;
    bool confidence = false;
    bool artifact_empty = false;
    bool artifact_temporary = false;
    bool artifact_missing = false;
    std::set<ByteString> hook_domains;
};

bool has(const std::set<ByteString>& domains, const ByteString& key) {
    return domains.find(key) != domains.end();
}

bool dense(const std::set<ByteString>& domains) {
    return has(domains, "combat") && has(domains, "network") &&
           (has(domains, "movement") || has(domains, "entity_render"));
}

// Interpretation: this compact function restates the generic rules reached by
// Aero/Xaero test fixtures. The authoritative recovered implementations live in
// the individual rule files named below; this file documents their combined
// behavior and does not represent a standalone original function.
std::vector<Rule> generic_routes(const GenericInputs& in) {
    std::vector<Rule> out;
    const bool unbacked = in.artifact_empty || in.artifact_temporary ||
                          in.artifact_missing;

    // Recovered in java_cluster_hook_rules.cpp: confidence, an unbacked
    // artifact, and at least two stored domain keys emit score 85.
    if (in.confidence && unbacked && in.hook_domains.size() > 1)
        out.push_back({"CLUSTER_ARTIFACT_HOOKS", 85});

    // Recovered in java_cluster_hook_rules.cpp: the dense predicate is exact:
    // combat + network + either movement or entity_render.
    if (in.confidence && unbacked && dense(in.hook_domains))
        out.push_back({"DENSE_CROSS_DOMAIN_HOOKS", 82});

    // Recovered: this higher-scoring dense rule has no direct confidence gate.
    if (unbacked && dense(in.hook_domains))
        out.push_back({"UNBACKED_CROSS_DOMAIN_HOOKS", 88});

    // Recovered in java_cluster_name_rules.cpp. These rules inspect class-name
    // categories in the bucket; neither rule compares an Aero/Xaero brand.
    if (in.explicit_module_names > 0)
        out.push_back({"EXPLICIT_CHEAT_MODULE", 95});
    if (in.gui_component_names >= 2 ||
        (in.gui_component_names == 1 &&
         in.lowered_namespace.find("client") != ByteString::npos))
        out.push_back({"MODULE_MANAGER_GUI", 88});
    return out;
}

// Recovered: "aero" and "xaero" are accepted as generic owner identifiers in
// Mixin-style names such as handler$nonce$aero$attack. Attribution still needs
// the same loader, exactly one nonempty artifact owner, exactly one namespace
// prefix through the parsed identifier, and at least one recognized hook domain.
//
// Recovered fixtures:
//   * ordinary aero.client, xaero.client and other.client produced no rule;
//   * a simple name KillAura produced EXPLICIT_CHEAT_MODULE (95) for all three;
//   * a 21-class/20-obfuscated Aero-owned cluster with combat + network emitted
//     CLUSTER_ARTIFACT_HOOKS (85);
//   * adding movement also emitted scores 82 and 88, with score 88 selected.
//
// Interpretation: Aero/Xaero behavior is generic owner and rule attribution,
// not a dedicated branded detector. No recovered decision compares against the
// literal brand names "aero" or "xaero".
// Review source only; never compiled or executed.
}
