#include "../../session/session_types.hpp"
#include <array>
#include <string_view>

namespace ocean::reconstructed::minecraft_sensitive_names_review {
struct Contracts {
    virtual ByteString original_unicode_lowercase(const ByteString&) = 0;
};

// wmECblIl_@1e653c0: case-sensitive substring membership; first hit wins.
template<std::size_t Count>
bool contains_any(
    const ByteString& text,
    const std::array<std::string_view, Count>& needles) {
    for (const auto needle : needles)
        if (text.find(needle) != ByteString::npos) return true;
    return false;
}

// wqiSy5s@1e9dc20
std::vector<ByteString> sensitive_categories(Contracts& runtime, const ByteString& name) {
    const auto lower = runtime.original_unicode_lowercase(name);
    std::vector<ByteString> categories;

    constexpr std::array<std::string_view, 7> network_terms = {
        "packet", "network", "nethandler", "channelread",
        "channelwrite", "sendmessage", "connection",
    };
    if (contains_any(lower, network_terms)) categories.emplace_back("network");

    constexpr std::array<std::string_view, 12> combat_terms = {
        "attack", "swing", "attackreach", "entityreach",
        "playerreach", "combatreach", "cooldown", "selectedslot", "hitresult",
        "interactentity", "interactionmanager", "playercontroller",
    };
    if (contains_any(lower, combat_terms)) categories.emplace_back("combat");

    constexpr std::array<std::string_view, 11> movement_terms = {
        "movement", "input", "keyboard", "mouse", "yaw",
        "pitch", "rotation", "velocity", "knockback", "push", "playermove",
    };
    if (contains_any(lower, movement_terms)) categories.emplace_back("movement");

    constexpr std::array<std::string_view, 5> entity_render_terms = {
        "renderentity", "entityrender", "glow", "nametag", "outline",
    };
    if (contains_any(lower, entity_render_terms))
        categories.emplace_back("entity_render");

    return categories;
}

// cGxA94@1e6e0c0
std::vector<ByteString> categories_for_mixin_class(
    Contracts& runtime,
    const ByteString& full_name) {
    const auto last_dot = full_name.rfind('.');
    const auto simple_name =
        last_dot == ByteString::npos ? full_name : full_name.substr(last_dot + 1);
    const auto lower = runtime.original_unicode_lowercase(simple_name);

    // Recovered: `mixin` or `accessor` may appear anywhere in the simple name;
    // neither term must be a suffix. Slash-separated names are left unchanged.
    if (lower.find("mixin") == ByteString::npos &&
        lower.find("accessor") == ByteString::npos)
        return {};
    return sensitive_categories(runtime, lower);
}

// Interpretation: these categories mark names associated with network, combat,
// movement, or entity-render behavior. They are inputs to later cluster scoring,
// not detections on their own. A standalone Aero or Xaero name has no category;
// a branded name containing terms such as `attack` or `packet` can still match.
// The term checks are substring based and intentionally allow overlapping
// categories. The original 129 classifier and 12 mixin-gate cases were checked.
// This readable reconstruction was never compiled or executed.
}
