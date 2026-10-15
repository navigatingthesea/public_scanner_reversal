#include "../../session/session_types.hpp"
#include <map>
#include <optional>
namespace ocean::reconstructed::minecraft_java_jvm_flags {
// Purpose: read HotSpot's JVMFlag table into a name -> bool cache used by
// later JVM checks. Only the first value byte is interpreted.
using Address = std::uint64_t;
template <class T> struct Read {
  T value;
  bool error = false;
};
struct Contracts {
  virtual std::optional<Address> static_address(Address reader,
                                                const ByteString &type,
                                                const ByteString &member) = 0;
  virtual std::optional<Address> field_offset(Address reader,
                                              const ByteString &type,
                                              const ByteString &member) = 0;
  virtual std::optional<std::uint64_t> type_size(Address reader,
                                                 const ByteString &type) = 0;
  virtual Read<Address> read_pointer(Address reader, Address) = 0;
  virtual Read<ByteString>
  read_c_string(Address reader,
                Address) = 0; // wvG7BYMkaXq6; separate native reader
  virtual Read<ByteString> read_bytes(Address reader, Address,
                                      std::uint64_t count) = 0;
  virtual std::map<ByteString, bool> &
  replace_flag_cache_with_empty_map(Address reader) = 0;
  [[noreturn]] virtual void panic_empty_successful_value_read() = 0;
};
// Recovered (n5cz3RaTi3b@1a5dce0): sync.Once callback.
void initialize(Contracts &rt, Address reader) {
  auto &flags = rt.replace_flag_cache_with_empty_map(
      reader); // reader72; always discard prior map first
  const auto table_address = rt.static_address(reader, "JVMFlag", "flags");
  const auto count_address = rt.static_address(reader, "JVMFlag", "numFlags");
  const auto stride = rt.type_size(reader, "JVMFlag");
  const auto name_offset = rt.field_offset(reader, "JVMFlag", "_name");
  const auto value_offset = rt.field_offset(reader, "JVMFlag", "_addr");
  if (!table_address || !count_address || !stride || !name_offset ||
      !value_offset)
    return;
  if (*stride < 16 || *stride > 256)
    return;
  const auto table = rt.read_pointer(reader, *table_address);
  const auto count =
      rt.read_pointer(reader, *count_address); // still read after table error
  if (table.error || count.error || count.value > 10000)
    return;
  for (std::uint64_t index = 0; index < count.value; ++index) {
    const Address entry =
        table.value + index * (*stride); // unsigned native address arithmetic
    const auto name_pointer = rt.read_pointer(reader, entry + *name_offset);
    if (name_pointer.error)
      continue;
    const auto name = rt.read_c_string(reader, name_pointer.value);
    if (name.error || name.value.empty())
      continue;
    const auto value_pointer = rt.read_pointer(reader, entry + *value_offset);
    if (value_pointer.error)
      continue;
    const auto value = rt.read_bytes(reader, value_pointer.value, 1);
    if (value.error)
      continue;
    if (value.value.empty())
      rt.panic_empty_successful_value_read();
    const auto byte = static_cast<unsigned char>(value.value[0]);
    if (byte < 2)
      flags[name.value] = (byte != 0); // last accepted duplicate wins
  }
}
// The original does not inspect the JVM flag type: a first byte of 0/1 is
// accepted for any nonempty name. Reads are single-pass; there is no snapshot
// stability retry, explicit null-table guard, or validation of later bytes.
// 17 original instruction-level fixtures: 16 normal returns and the original
// bounds panic for an empty successful value read. Synthetic VM tables/native
// reads only; guest-only reconstruction, never compiled or executed.
} // namespace ocean::reconstructed::minecraft_java_jvm_flags
