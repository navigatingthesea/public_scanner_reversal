#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Two captured NVIDIA ShadowPlay FTS registry locations.
//   Gate: Requires a successful integer read exactly equal to uint64 36.
//   Output: Emits one warning and one ShadowPlay debug row, then stops.
//   Failure: Open/read failures skip a location; close failure is ignored.

namespace ocean::reconstructed::shadowplay_registry_review {
struct OpenResult {
    std::uint64_t handle=0;
    bool has_error=false;
};
struct IntegerResult {
    std::uint64_t value=0;
    bool has_error=false;
};
struct RegistryContracts {
 virtual OpenResult original_open_hklm(const ByteString& key,std::uint32_t access)=0;
 virtual IntegerResult original_integer_value(std::uint64_t handle,const ByteString& value_name)=0;
 virtual void original_close_key_ignoring_result(std::uint64_t handle)=0;
 virtual void append_warning(const ByteString&)=0; //572e7a0 -> WARNINGS
 virtual void append_debug(const std::vector<ByteString>&)=0; //572e8e0 -> DEBUG_DETECTIONS
};
// Captured location slice56632b0, in original iteration order. Mutable global
// contents are a snapshot, not an initializer/session immutability proof.
std::vector<ByteString> captured_shadowplay_locations() {return {
 "SOFTWARE\\NVIDIA Corporation\\Global\\NvApp\\ShadowPlay\\FTS",
 "SOFTWARE\\WOW6432Node\\NVIDIA Corporation\\Global\\NvApp\\ShadowPlay\\FTS"
};}
// XNbiSvU@12c02c0. Exact uint64 equality36, no bitmask or low-DWORD test.
// Open/read failures skip that location. Close occurs immediately after read,
// including read-error cases. Stops at the first match and records its path.
void check(RegistryContracts& r,const std::vector<ByteString>& locations) {
 for(const auto& key:locations) {
  const auto opened=r.original_open_hklm(key,1);if(opened.has_error) continue;
  const auto value=r.original_integer_value(opened.handle,"{497B8458-4244-4EE6-BFEA-F3D2BA294F21}");
  r.original_close_key_ignoring_result(opened.handle);
  if(value.has_error || value.value!=36) continue;
  r.append_warning("ShadowPlay modified to bypass Streamproof");
  r.append_debug({"Detect","ShadowPlay","FTS 0x24 @ HKLM\\"+key});return;
 }
}
// The warning is the program's interpretation. This routine only reads this
// registry value; it does not verify actual capture behavior or who changed it.
}
