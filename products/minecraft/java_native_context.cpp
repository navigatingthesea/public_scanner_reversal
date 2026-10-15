#include "../../session/session_types.hpp"
#include <unordered_map>
#include <vector>
namespace ocean::reconstructed::minecraft_java_native_context {
// Recovered: snapshot JVM object-header flags and narrow-pointer encodings, then
// index every collected class by its native Klass address for later validation.
// The map is a lookup cache, not a monitored-class allowlist or detector list.
using Address = std::uint64_t;
struct KnownFlag {
    bool value = false, known = false;
};
struct NarrowEncoding {
    Address base = 0;
    std::uint32_t shift = 0;
    bool valid = false;
};
template <class Class> struct Context { // gdwyKn2/native56bytes,logicalC++layout
    Address reader = 0;
    KnownFlag zgc;              // value8,known9
    KnownFlag compressed_oops;  // value10,known11
    NarrowEncoding oop;         // base16,shift24;validstoredincompressed_oops.known
    KnownFlag compact_headers;  // value28,known29
    KnownFlag compressed_klass; // value30,known31
    NarrowEncoding klass;       // base32,shift40;validstoredincompressed_klass.known
    std::unordered_map<Address, const Class *> class_records; // 48,klass->pointerintoinputslice
};
struct Contracts {
    virtual KnownFlag flag(Address reader,
                           const ByteString &name) = 0; // rc2Ltk@1a5dc20,lazyflagcache
    virtual NarrowEncoding narrow_encoding(Address reader, const ByteString &type,
                                           const ByteString &member) = 0; // avrHwkg9@1a9a260
};
template <class Class>
Context<Class> build(Contracts &rt, Address reader,
                     const std::vector<Class> &classes) { // giKoajRC@1a862c0
    Context<Class> out;
    out.reader = reader;
    for (const auto &klass : classes)
        out.class_records[klass.klass] = &klass; // lastduplicatewins,zeroallowed
    out.zgc = rt.flag(reader, "UseZGC");
    out.compact_headers = rt.flag(reader, "UseCompactObjectHeaders");
    out.compressed_oops = rt.flag(reader, "UseCompressedOops");
    out.compressed_klass = rt.flag(reader, "UseCompressedClassPointers");
    if (out.compressed_oops.value && out.compressed_oops.known) {
        out.oop = rt.narrow_encoding(reader, "CompressedOops", "_narrow_oop");
        // Recovered: retain the attempted base/shift values, but clear "known"
        // when HotSpot's narrow-oop encoding cannot be resolved.
        out.compressed_oops.known = out.oop.valid;
    }
    if (out.compressed_klass.value && out.compressed_klass.known) {
        out.klass = rt.narrow_encoding(reader, "CompressedKlassPointers", "_narrow_klass");
        out.compressed_klass.known = out.klass.valid;
    }
    return out;
}
// Recovered: 15 return paths cover known/unknown flag combinations, independent
// oop and Klass encodings, invalid narrow configurations, and duplicate Klass
// addresses (last record wins). The input class vector must outlive this context
// because the map stores pointers into it.
// Unresolved: flag-cache and narrow-encoding providers remain external contracts;
// no fixed JVM flag values or addresses were inferred from fixtures.
} // namespace ocean::reconstructed::minecraft_java_native_context
