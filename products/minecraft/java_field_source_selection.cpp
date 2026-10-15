#include "../../session/session_types.hpp"
#include <optional>
#include <vector>

namespace ocean::reconstructed::minecraft_java_field_selection {
using Address = std::uint64_t;

template<class FieldRecord>
using FieldList = std::optional<std::vector<FieldRecord>>;

template<class FieldRecord>
struct Contracts {
    virtual FieldList<FieldRecord> encoded_fields(
        Address reader,
        Address klass,
        Address pool) = 0; // cgUD/source172
    virtual FieldList<FieldRecord> legacy_fields(
        Address reader,
        Address klass,
        Address pool) = 0; // gXa/source173
};

template<class FieldRecord>
FieldList<FieldRecord> collect(
    Contracts<FieldRecord>& runtime,
    Address reader,
    Address klass,
    Address raw_pool) { // urkIBPqcmZU@1a4b620
    if (raw_pool == 0) return {};

    auto encoded = runtime.encoded_fields(reader, klass, raw_pool);
    if (encoded.has_value()) return encoded;
    return runtime.legacy_fields(reader, klass, raw_pool);
}

// Recovered: the encoded-field parser has priority. `nullopt` corresponds to a
// nil Go slice data pointer and enables the legacy fallback; a present but empty
// vector suppresses fallback. Selection requires a raw native pool address and
// does not depend on whether the parsed-pool snapshot succeeded. Six original
// selector paths were checked. This readable source was never compiled or run.
}
