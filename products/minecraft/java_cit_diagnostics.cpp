#include "../../session/session_types.hpp"
namespace ocean::reconstructed::minecraft_cit_diagnostic_review {
// Purpose: turn the resource-pack CIT collector's records into the exact
// warning and debug rows emitted by the application.
//
// The original 64-byte record contains a 16-byte pack-name string followed by
// two 24-byte Go slices. The producer is reconstructed in
// java_cit_properties.cpp.
struct CITRecord {
  ByteString original_pack_name;
  std::vector<ByteString> qualifying_items; // sorted by the producer
  std::vector<ByteString> property_paths;   // globally capped at eight
};
struct CITDiagnosticContracts {
  virtual void append_warning(const ByteString &) = 0; // 572e7a0 -> WARNINGS
  virtual void append_debug(
      const std::vector<ByteString> &) = 0; // 572e8e0 -> DEBUG_DETECTIONS
  virtual ByteString original_format_count_title(
      GoInt) = 0; //"%d Durability-color armor pack(s) found"
  virtual ByteString
  original_format_count_description(GoInt, const ByteString &pack_names) = 0;
  //"The user has %d resource pack(s) that color armor by remaining durability
  // using OptiFine/MCPatcher CIT: %s"
};
ByteString join_exact(const std::vector<ByteString> &values,
                      const ByteString &sep) {
  ByteString out;
  for (std::size_t k = 0; k < values.size(); ++k) {
    if (k)
      out += sep;
    out += values[k];
  }
  return out;
}
// nmJf9uh@1bf3940. Empty input returns without output; every input record
// creates a five-string debug row. It does not validate or deduplicate lists
// here, and even a record with two empty lists contributes to the final count
// and warning. Caller JEg@1c5fa60 passes the CIT slice at Nl result offsets
// 32/40/48, not the detected-pack slice at offset 8, suspected packs at 80,
// or names-only slice at 56.
void report_cit_records(CITDiagnosticContracts &r,
                        const std::vector<CITRecord> &records) {
  if (records.empty())
    return;
  std::vector<ByteString> names;
  for (const auto &record : records) {
    names.push_back(record.original_pack_name);
    r.append_debug({"Detect", "JavaCITDurability", record.original_pack_name,
                    join_exact(record.qualifying_items, ","),
                    join_exact(record.property_paths, ",")});
  }
  const auto count = static_cast<GoInt>(records.size());
  r.append_warning(
      r.original_format_count_title(count) + ":::Resource Packs folder:::" +
      r.original_format_count_description(count, join_exact(names, ", ")));
}
} // namespace ocean::reconstructed::minecraft_cit_diagnostic_review
