#include "../session/session_types.hpp"
#include <optional>
// Recovered behavior summary:
//   Input: Trimmed encrypted rule material and the registered password list in captured order.
//   Gate: Accepts the first nonempty decryption that is valid JSON or contains case-sensitive
//         import or YARA.
//   Output: Moves and wipes that plaintext into a frozen protected buffer and returns its handle.
//   Failure: Empty inputs, failed decryptions, failed validation, or exhausted keys return zero;
//            protected-buffer failures retain panic behavior.

namespace ocean::reconstructed::rule_material_decoder {

using ProtectedBuffer = std::uintptr_t;

struct Contracts {
    virtual ByteString trim_unicode_space(const ByteString&) = 0;
    virtual std::optional<ByteString> decrypt_salted(
        const ByteString&, const ByteString& key) = 0;
    virtual bool json_valid(const ByteString&) = 0;
    virtual ProtectedBuffer protected_new(std::size_t) = 0;
    virtual std::size_t protected_length(ProtectedBuffer) = 0;
    virtual void protected_move_at_zero_and_wipe_input(
        ProtectedBuffer, ByteString&) = 0;
    virtual void protected_freeze_or_go_panic(ProtectedBuffer) = 0;
};

ProtectedBuffer protect(Contracts& runtime,
                        ByteString& plaintext) { // MzwRnQjpb @ 0x10a8100
    const auto protected_buffer = runtime.protected_new(plaintext.size());
    if (runtime.protected_length(protected_buffer) == 0) {
        return protected_buffer;
    }

    // MoveAt @ 0x10a81a0 checks Alive, locks the buffer, checks destination
    // offset zero, copies, wipes the original nonempty input, and unlocks.
    runtime.protected_move_at_zero_and_wipe_input(protected_buffer, plaintext);
    runtime.protected_freeze_or_go_panic(protected_buffer);
    return protected_buffer;
}

ProtectedBuffer decode(
    Contracts& runtime,
    const ByteString& input,
    const std::vector<ByteString>& registered_keys) { // LKBNKzeKfuh0 @ 0x10acd60
    const auto encrypted = runtime.trim_unicode_space(input);
    if (encrypted.empty()) {
        return 0;
    }

    // Global RVAs 0x572e2e0/0x572e2e8/0x572e2f0 preserve key order.
    for (const auto& raw_key : registered_keys) {
        const auto key = runtime.trim_unicode_space(raw_key);
        if (key.empty()) {
            continue;
        }

        auto plaintext = runtime.decrypt_salted(encrypted, key);
        if (!plaintext || plaintext->empty()) {
            continue;
        }

        // This is a validity heuristic, not a signature or semantic parser.
        // Both byte tests are case-sensitive substrings anywhere in the data.
        const bool accepted =
            runtime.json_valid(*plaintext) ||
            plaintext->find("import") != ByteString::npos ||
            plaintext->find("YARA") != ByteString::npos;
        if (accepted) {
            return protect(runtime, *plaintext);
        }
    }
    return 0;
}

// Ten original selector routes cover empty input/key/plaintext, key fallback,
// and the exact JSON/import/YARA gates. This helper does not validate compiled
// native rules; the PowerShell caller separately attempts library ReadRules.

}  // namespace ocean::reconstructed::rule_material_decoder
