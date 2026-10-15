#include "../../session/session_types.hpp"
#include <map>
namespace ocean::reconstructed::minecraft_library_name_gate_review {
// Purpose: suppress selected name-based rules for known Minecraft/library
// namespaces. This predicate is narrower than the separate whole-class SDK
// exclusion and must not be used as a general library classifier.
struct Contracts {
  virtual ByteString original_unicode_lowercase(const ByteString &) = 0;
};
using SubpackageMap = std::map<ByteString, bool>;
bool starts(const ByteString &value, const ByteString &prefix) {
  return value.size() >= prefix.size() &&
         value.compare(0, prefix.size(), prefix) == 0;
}
// Exact original QaD.init prefix stores24true keys into global5729200.
// This is a DIFFERENT map from the43mod-ID map5729020 that contains xaero.
SubpackageMap captured_minecraft_subpackages() {
  SubpackageMap map;
  for (const ByteString key :
       {"block",    "chat",       "client",   "core",     "data",
        "entity",   "item",       "nbt",      "network",  "realms",
        "screen",   "server",     "sounds",   "stats",    "state",
        "tags",     "util",       "world",    "main",     "advancements",
        "commands", "datafixers", "gametest", "resources"})
    map[key] = true;
  return map;
}
// jU9EPGrcqo9@1e62e40. Positive gate suppresses yrn/zilq/GUI name-rule inputs
// in g2; it does not mean the whole class record was excluded from all SDK
// scans. The gOg full class/member exclusion remains a separate, earlier
// predicate.
bool library_or_known_minecraft_name(Contracts &runtime,
                                     const SubpackageMap &known,
                                     const ByteString &full_name) {
  const auto lower = runtime.original_unicode_lowercase(full_name);
  const ByteString minecraft = "net.minecraft.";
  if (starts(lower, minecraft)) {
    auto rest = lower.substr(minecraft.size());
    const auto dot = rest.find('.');
    if (dot != ByteString::npos)
      rest.resize(dot);
    const auto found = known.find(rest);
    return found != known.end() && found->second;
  }
  for (const ByteString prefix :
       {"com.mojang.", "net.fabricmc.", "org.spongepowered.", "org.quiltmc.",
        "net.minecraftforge.", "net.neoforged.", "org.lwjgl.", "io.github.",
        "com.github.", "org.slf4j.", "org.apache.", "com.google.",
        "org.jetbrains.", "me.jellysquid."})
    if (starts(lower, prefix))
      return true;
  // Two additional bare PREFIX tests, deliberately lacking a dot/boundary.
  // org.slf4jx and net.fabricmcx pass these; xorg.slf4j/p.org.slf4j do not.
  return starts(lower, "org.slf4j") || starts(lower, "net.fabricmc");
}
// Evidence: 20 direct-helper, 30 loaded-map, 62 prefix, eight GUI, and 15
// module fixtures. For net.minecraft.*, the first remaining segment must map
// to true: client/CLIENT pass; clientx, unknown, class_123, and KillAura fail.
// gOg separately excludes net.minecraft.* in other SDK paths, so the two
// predicates must remain distinct. The captured initializer contains 24 keys.
// No Aero/Xaero brand verdict is made here; aero.KillAura can still score 95
// through the separate explicit-module rule. Review source only.
} // namespace ocean::reconstructed::minecraft_library_name_gate_review
