#include "efi_evidence_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: Five firmware strings from the recovered registry/provider path.
//   Gate: A nonempty primary value wins; fallback is used only for an empty value, without trimming
//         or case normalization.
//   Output: Returns BIOS vendor/version and baseboard manufacturer/product/version.
//   Failure: Read errors become empty strings; whitespace-only values suppress fallback.

namespace ocean::reconstructed::efi_bios_input {
using efi_evidence::SystemFirmwareInfo;
struct Contracts {
 virtual std::uintptr_t open_hklm_or_zero(const ByteString&,std::uint32_t access)=0;
 virtual void with_deferred_close(std::uintptr_t,const std::function<void()>&)=0;
 virtual std::optional<ByteString> get_string(std::uintptr_t,const ByteString&)=0;
};
SystemFirmwareInfo collect(Contracts& rt){ //ptrVxWaE@12768e0
 SystemFirmwareInfo result;
 const auto key=rt.open_hklm_or_zero(R"(HARDWARE\DESCRIPTION\System\BIOS)",0x20019);if(!key)return result;
 rt.with_deferred_close(key,[&]{
  const auto read=[&](const ByteString& name){return rt.get_string(key,name).value_or("");};
  result.bios_vendor=read("BIOSVendor");result.bios_version=read("BIOSVersion");
  result.board_manufacturer=read("BaseBoardManufacturer");
  result.board_product=read("BaseBoardProduct");result.board_version=read("BaseBoardVersion");
  if(result.board_manufacturer.empty())result.board_manufacturer=read("SystemManufacturer");
  if(result.board_product.empty())result.board_product=read("SystemProductName");
 });return result;
}
//8 original routes: open/read/empty/fallback/whitespace. No trimming or case
//normalization; whitespace-only value prevents fallback. Errors become empty.
//Returns five raw strings, not a stable HWID by itself. Guest-only, never run.
}
