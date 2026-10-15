#include "../../session/session_types.hpp"

namespace ocean::reconstructed::minecraft_additional_name_predicates_review {
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
};

bool starts_with(const ByteString& text, const ByteString& prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const ByteString& text, const ByteString& suffix) {
    return text.size() >= suffix.size() &&
        text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void remove_one_suffix(ByteString& text, const ByteString& suffix) {
    if (ends_with(text, suffix)) text.resize(text.size() - suffix.size());
}

// aFQyBH_Z_jUW@1e657c0, captured 26-key table at 0x56639b0.
bool broader_module_identifier(Contracts& runtime, const ByteString& input) {
    auto normalized = runtime.original_unicode_lowercase(input);

    // Recovered: each suffix is removed at most once and in this exact order.
    remove_one_suffix(normalized, "module");
    remove_one_suffix(normalized, "util");
    remove_one_suffix(normalized, "utils");

    static constexpr const char* keywords[] = {
        "aura", "esp", "speed", "fly", "step", "clicker", "blink",
        "nofall", "reach", "velocity", "trigger", "aimassist", "scaffold",
        "fastbreak", "autotool", "invmanager", "autoarmor", "autopot",
        "refill", "exploit", "tracers", "hitboxes", "nametags", "vanish",
        "noclip", "freecam",
    };

    for (const ByteString keyword : keywords) {
        if (normalized == keyword ||
            starts_with(normalized, keyword + "$") ||
            ends_with(normalized, "$" + keyword) ||
            starts_with(normalized, keyword + "-"))
            return true;
    }
    return false;
}

// ykuUoaP27@1e6e020.
bool contains_mods_path_component(Contracts& runtime, const ByteString& input) {
    if (input.empty()) return false;

    const auto normalized_path = runtime.original_unicode_lowercase(input);
    std::size_t component_start = 0;
    for (std::size_t cursor = 0; cursor <= normalized_path.size(); ++cursor) {
        if (cursor != normalized_path.size() &&
            normalized_path[cursor] != '/' && normalized_path[cursor] != '\\')
            continue;

        if (cursor - component_start == 4 &&
            normalized_path.compare(component_start, 4, "mods") == 0)
            return true;
        component_start = cursor + 1;
    }
    return false;
}

// Interpretation: `broader_module_identifier` marks names shaped like common
// cheat-module identifiers. It is separate from the 23-key predicate in
// java_name_rule_predicates.cpp and does not emit a score or verdict itself.
// Aero, Xaero, KillAura, Aimbot, and Triggerbot do not match this 26-key helper.
//
// Recovered: yku.func1@1eaefa0 compares runes to slash and backslash;
// `contains_mods_path_component` therefore splits only on those separators
// and requires an exact component named "mods". It does not canonicalize paths,
// access the filesystem, or inspect extensions. Forty-one original paths were
// checked. This readable reconstruction was never compiled or executed.
}
