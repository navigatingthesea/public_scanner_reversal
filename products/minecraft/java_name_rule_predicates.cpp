#include "../../session/session_types.hpp"

namespace ocean::reconstructed::minecraft_java_name_rule_review {
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
    virtual std::vector<ByteString> original_fields_by_rune_predicate(
        const ByteString&, bool (*separator)(std::int32_t)) = 0;
    virtual const std::vector<ByteString>& current_gui_identifiers() = 0;   // 0x5663970
    virtual const std::vector<ByteString>& current_cheat_identifiers() = 0; // 0x5663990
};

bool gui_separator(std::int32_t rune) { return rune == '$' || rune == '_'; } // fj9.func1@1eb0980
bool temporary_path_separator(std::int32_t rune) { // cf.func1@1eafd20
    return rune == '/' || rune == '\\' || rune == '.' || rune == '-' || rune == '_';
}
bool cheat_token_separator(std::int32_t rune) { // zilq.func1@1eb06a0
    return rune == '$' || rune == '_' || rune == '-' || rune == ' ';
}

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

// etQ4Ctt@1e62d40
bool intermediary_class_number(const ByteString& name) {
    if (!starts_with(name, "class_") || name.size() == 6) return false;
    for (std::size_t index = 6; index < name.size(); ++index)
        if (name[index] < '0' || name[index] > '9') return false;
    return true;
}

// fj9@1e652e0
bool contains_gui_identifier(Contracts& runtime, const ByteString& input) {
    const auto lower = runtime.original_unicode_lowercase(input);
    const auto tokens = runtime.original_fields_by_rune_predicate(lower, gui_separator);
    for (const auto& token : tokens)
        for (const auto& keyword : runtime.current_gui_identifiers())
            if (token == keyword) return true;
    return false;
}

// cf@1e6b680
bool contains_temporary_component(Contracts& runtime, const ByteString& input) {
    const auto lower = runtime.original_unicode_lowercase(input);
    const auto components =
        runtime.original_fields_by_rune_predicate(lower, temporary_path_separator);
    for (const auto& component : components)
        if (component == "temp" || component == "tmp") return true;
    return false;
}

// yrn@1e65480
bool sensitive_module_identifier(Contracts& runtime, const ByteString& input) {
    auto normalized = runtime.original_unicode_lowercase(input);

    // Recovered: remove each suffix at most once, in this exact order.
    remove_one_suffix(normalized, "module");
    remove_one_suffix(normalized, "util");
    remove_one_suffix(normalized, "utils");

    for (const auto& keyword : runtime.current_cheat_identifiers()) {
        if (normalized == keyword ||
            starts_with(normalized, keyword + "$") ||
            ends_with(normalized, "$" + keyword) ||
            starts_with(normalized, keyword + "-"))
            return true;
    }
    return false;
}

// zilq@1e65b00
bool sensitive_cheat_token(Contracts& runtime, const ByteString& input) {
    const auto lower = runtime.original_unicode_lowercase(input);
    const auto tokens = runtime.original_fields_by_rune_predicate(lower, cheat_token_separator);

    for (const auto& token : tokens) {
        // Captured table entries permit up to five trailing bytes.
        for (const auto& keyword : runtime.current_cheat_identifiers())
            if (starts_with(token, keyword) && token.size() <= keyword.size() + 5)
                return true;

        // Recovered special cases require 1..8 trailing bytes. The bare prefix
        // does not satisfy this branch unless the captured table handles it.
        for (const ByteString prefix : {"aimassist", "triggerbot", "killaura", "bowaimbot"})
            if (starts_with(token, prefix) &&
                token.size() > prefix.size() && token.size() <= prefix.size() + 8)
                return true;
    }
    return false;
}

std::vector<ByteString> captured_gui_identifiers() {
    return {"modulebutton", "modulepanel", "categorypanel", "modulemanager",
            "clickgui", "clickguiscreen", "clickguibutton", "moduelbutton"};
}

std::vector<ByteString> captured_cheat_identifiers() {
    return {"killaura", "aimbot", "bowaimbot", "triggerbot", "autoclicker",
            "xray", "storageesp", "playeresp", "blockesp", "holeesp",
            "cheststealer", "boatfly", "elytrafly", "packetfly", "noknockback",
            "criticals", "antibot", "fakelag", "disabler", "spammer", "nuker",
            "lagreach", "fastplace"};
}

// Recovered check meanings:
// - intermediary_class_number: exact lowercase `class_` plus ASCII digits.
// - contains_gui_identifier: whole tokens split only on `$` and `_`.
// - contains_temporary_component: exact `temp`/`tmp` path-like component.
// - sensitive_module_identifier and sensitive_cheat_token: name-shape matches
//   against the captured cheat-identifier table with the boundaries above.
//
// Interpretation: these are evidence predicates. They return booleans without
// emitting a detection; g2S2a8As@1e7b320 combines them with other conditions.
// etQ also feeds bwmlUDVXsXcd@1e74360, and cf feeds gdhIEuqJG6l@1e73880.
// Unicode lowercase and FieldsFunc behavior remain runtime contracts. This
// readable reconstruction was never compiled or executed.
}
