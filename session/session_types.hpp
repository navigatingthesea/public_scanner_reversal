#pragma once
#include "../../common/review_contracts.hpp"
#include <map>
#include <vector>

namespace ocean::reconstructed {
struct StringList {
    // Go distinguishes a nil slice from an allocated zero-length slice.
    bool has_backing_storage = false;
    std::vector<ByteString> items;
};

// Readable logical view of the recovered response. Offset comments refer to the
// original Go record; this C++ struct is not a binary-compatible replacement.
struct SessionResponse {
    bool success = false;                    // JSON `s`, offset 0
    ByteString field_f;                      // JSON `f`, offset 8
    ByteString game_selector;                // JSON `t`, offset 24
    ByteString field_cs;                     // JSON `cs`, offset 40
    ByteString field_rh;                     // JSON `rh`, offset 56
    StringList field_hl;                     // JSON `hl`, offset 72
    ByteString field_l;                      // JSON `l`, offset 96
    ByteString field_sus;                    // JSON `sus`, offset 112
    ByteString field_rd;                     // offset 128
    ByteString field_ru;                     // offset 144
    ByteString field_jajaae;                 // offset 160
    ByteString field_jajaae2;
    ByteString field_h;
    ByteString field_LDET;                   // through offset 208
    std::map<ByteString, ByteString> field_d; // JSON `d`
};

// Unresolved: the exact names/meanings of obfuscated fields remain unknown.
// Evidence for every type, offset, JSON tag, and nested `d` field remains in
// review_evidence and recovered_reference. Modeling `d` as a map does not
// reproduce Go fixed-struct handling of unknown JSON fields, so unmarshal stays
// an explicit contract in pin_validation.cpp.

struct ValidatedSession {
    ByteString field_f;
    ByteString pin_input;
    ByteString field_cs;
    ByteString field_rh;
    StringList field_hl;
    ByteString field_sus;
    ByteString field_l;
};

struct SessionCache {
    struct RetainedFields {
        ByteString field_f;
        ByteString game_selector;
        ByteString field_cs;
        ByteString field_rh;
        StringList field_hl;
        ByteString field_l;
        ByteString field_sus;
    };

    ByteString pin_input;
    RetainedFields retained_fields;
};
}
