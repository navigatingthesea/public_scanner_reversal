#include "../../session/session_types.hpp"
#include <optional>
#include <utility>
namespace ocean::reconstructed::minecraft_java_context_providers {
// Purpose: recover two pieces of HotSpot decoding context: compressed-pointer
// base/shift pairs and cached boolean JVM flags. All memory reads remain
// provider calls so the reconstruction does not touch a live JVM.
using Address = std::uint64_t;
struct KnownFlag {
  bool value = false, known = false;
};
struct NarrowEncoding {
  Address base = 0;
  std::uint32_t shift = 0;
  bool valid = false;
};
template <class T> struct Read {
  T value;
  bool error = false;
};
struct Contracts {
  virtual std::optional<Address>
  vm_static_address(Address reader, const ByteString &type,
                    const ByteString &member) = 0;
  virtual Read<Address> read_pointer(Address reader, Address) = 0;
  virtual Read<std::uint32_t> read32(Address reader, Address) = 0;
  virtual bool flags_once_initialized(Address reader) = 0; // reader + 56
  virtual void
  initialize_flags_once(Address reader) = 0; // sync.Once.Do(n5cz3RaTi3b); body
                                             // reconstructed separately
  virtual KnownFlag cached_flag(
      Address reader,
      const ByteString &) = 0; // bool map at reader + 72; Go comma-ok lookup
};
std::optional<std::pair<Address, Address>> find_narrow_encoding_addresses(
    Contracts &rt, Address reader, const ByteString &type,
    const ByteString &member) { // tFiIPzKj4yLk@1a9a340
  for (const auto &prefix : {member + ".", ByteString{}}) {
    const auto base = rt.vm_static_address(reader, type, prefix + "_base");
    // The original performs both lookups before deciding whether this pair is
    // complete.
    const auto shift = rt.vm_static_address(reader, type, prefix + "_shift");
    if (base && shift)
      return std::make_pair(*base, *shift);
  }
  // Do not combine a prefixed base with an unprefixed shift (or vice versa).
  // A zero address still counts as a present lookup result.
  return std::nullopt;
}
NarrowEncoding narrow_encoding(Contracts &rt, Address reader,
                               const ByteString &type,
                               const ByteString &member) { // avrHwkg9@1a9a260
  const auto addresses =
      find_narrow_encoding_addresses(rt, reader, type, member);
  if (!addresses)
    return {};
  const auto base = rt.read_pointer(reader, addresses->first);
  // The shift read still occurs if the base read reports an error.
  const auto shift = rt.read32(reader, addresses->second);
  // Zero base and zero shift are valid. Even on a read error or an excessive
  // shift, the original values are retained while valid is set to false.
  return {base.value, shift.value,
          !base.error && !shift.error && shift.value <= 16};
}
KnownFlag flag(Contracts &rt, Address reader,
               const ByteString &name) { // rc2Ltk@1a5dc20
  if (!rt.flags_once_initialized(reader))
    rt.initialize_flags_once(reader);
  // Missing/nil map entries return {value=false, known=false}. A stored false
  // value returns {value=false, known=true}.
  return rt.cached_flag(reader, name);
}
// Evidence: 16 original flag/narrow-reader routes and eight original static
// address lookup routes. The prefixed "_narrow_oop._base/_shift" form is tried
// before bare "_base/_shift". Fixtures cover partial-pair fallback, zero
// addresses, shifts 16/17, read errors, and zero values. The sync.Once flag
// initializer is a separate reconstructed table loader; it is not modeled as
// an empty map. Review source only; no live JVM query or execution.
} // namespace ocean::reconstructed::minecraft_java_context_providers
