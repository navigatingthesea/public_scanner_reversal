#include "efi_evidence_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: Secure Boot registry values plus one-byte UEFI variables under the captured vendor GUID.
//   Gate: Registry enabled requires exact value 1; firmware booleans require a successful
//         nonzero-length read and byte 1.
//   Output: Returns SecureBootState including consistency, policy publisher, mode flags, and update
//           metadata.
//   Failure: Missing main inputs collapse to false while optional fields preserve unknown; provider
//            errors do not become successful reads.

namespace ocean::reconstructed::efi_secureboot_input {
using efi_evidence::SecureBootState;using Handle=std::uintptr_t;
struct IntegerResult {
    std::uint64_t value;
    bool error;
};
struct StringResult {
    ByteString value;
    bool error;
};
struct Utf16 {
    std::uintptr_t pointer;
    bool error;
    std::size_t length;
};
struct NativeResult {
    std::uintptr_t value,last_error;
};
struct Contracts {
 virtual Handle new_system_lazy_dll(const ByteString&)=0;
 virtual Handle new_lazy_proc(Handle,const ByteString&)=0;
 virtual Utf16 utf16_from_string(const ByteString&)=0;
 virtual NativeResult call_firmware_variable(Handle proc,std::uintptr_t variable,
  std::uintptr_t vendor_guid,std::uint8_t* buffer,std::uint32_t length)=0;
 virtual Handle open_hklm_or_zero(const ByteString&,std::uint32_t access)=0;
 virtual void with_deferred_close(Handle,const std::function<void()>&)=0;
 virtual IntegerResult get_integer(Handle,const ByteString&)=0;
 virtual StringResult get_string(Handle,const ByteString&)=0;
 virtual void go_panic_bounds()=0;
};
std::optional<std::uint8_t> firmware_byte(Contracts& rt,const ByteString& variable){ //eSI3YnWcA8Y@1266ec0
 const auto dll=rt.new_system_lazy_dll("kernel32.dll");
 const auto proc=rt.new_lazy_proc(dll,"GetFirmwareEnvironmentVariableW");
 const auto name=rt.utf16_from_string(variable);
 if(!name.error && name.length==0)rt.go_panic_bounds();
 const auto guid=rt.utf16_from_string("{8be4df61-93ca-11d2-aa0d-00e098032b8c}");
 if(!guid.error && guid.length==0)rt.go_panic_bounds();
 std::uint8_t value=0;
 const auto native=rt.call_firmware_variable(proc,name.error?0:name.pointer,
  guid.error?0:guid.pointer,&value,1);
 if(native.value==0)return std::nullopt;
 return value; //last_error ignored, any nonzero return accepted
 //UTF16 error does not abort: null pointer is still passed to API. Positive
 //synthetic result on that route proves control only, not real Windows success.
 //New lazy DLL/proc descriptors per call; no explicit DLL release in this helper.
}
std::optional<bool> firmware_boolean(Contracts& rt,const ByteString& variable){ //yXKBYJ@12677a0
 const auto byte=firmware_byte(rt,variable);if(!byte)return std::nullopt;
 return *byte==1; //2/255 are false, not truthy
}
bool secure_boot_enabled(Contracts& rt){ //CBCcTVJNnS@1267b40
 const auto byte=firmware_byte(rt,"SecureBoot");return byte && *byte==1;
}
std::optional<std::uint32_t> optional_integer(Contracts& rt,const ByteString& path,const ByteString& name){ //vB_tlxlex@1267820
 const auto key=rt.open_hklm_or_zero(path,1);if(!key)return std::nullopt;
 std::optional<std::uint32_t> result;
 rt.with_deferred_close(key,[&]{const auto value=rt.get_integer(key,name);if(!value.error)result=static_cast<std::uint32_t>(value.value);});
 return result; //successful0 retained; high32bits discarded
}
std::optional<ByteString> optional_string(Contracts& rt,const ByteString& path,const ByteString& name){ //jZ5lM8C@12679a0
 const auto key=rt.open_hklm_or_zero(path,1);if(!key)return std::nullopt;
 std::optional<ByteString> result;
 rt.with_deferred_close(key,[&]{const auto value=rt.get_string(key,name);if(!value.error)result=value.value;});
 return result; //successful empty/whitespace retained, no trimming
}
SecureBootState collect(Contracts& rt){ //y_LztuEZq@1268000, Go112-byte return
 SecureBootState result;
 const auto key=rt.open_hklm_or_zero(R"(SYSTEM\CurrentControlSet\Control\SecureBoot\State)",1);
 if(key){
  const auto enabled=rt.get_integer(key,"UEFISecureBootEnabled");
  result.registry_enabled=!enabled.error && enabled.value==1;
  //This field retains the string EVEN when GetStringValue also returns error.
  result.policy_publisher=rt.get_string(key,"PolicyPublisher").value;
  rt.with_deferred_close(key,[]{}); //original explicit close before firmware calls
 }
 result.firmware_enabled=secure_boot_enabled(rt);
 result.consistent=result.registry_enabled==result.firmware_enabled;
 result.setup_mode=firmware_boolean(rt,"SetupMode");
 result.audit_mode=firmware_boolean(rt,"AuditMode");
 result.deployed_mode=firmware_boolean(rt,"DeployedMode");
 result.vendor_keys=firmware_boolean(rt,"VendorKeys");
 const ByteString base=R"(SYSTEM\CurrentControlSet\Control\SecureBoot)";
 const ByteString servicing=base+R"(\Servicing)";
 result.available_updates=optional_integer(rt,base,"AvailableUpdates");
 result.available_updates_policy=optional_integer(rt,base,"AvailableUpdatesPolicy");
 result.uefica2023_status=optional_string(rt,servicing,"UEFICA2023Status").value_or("");
 result.uefica2023_error=optional_integer(rt,servicing,"UEFICA2023Error");
 result.windows_uefica2023_capable=optional_integer(rt,servicing,"WindowsUEFICA2023Capable");
 return result;
 //fake_policy_guid remains false in this constructor. A separate classifier
 //examines policy/consistency and emits findings. Missing registry/API readings
 //both collapse to false for the two main flags, so consistent can be true even
 //when BOTH inputs failed. Optional mode/update fields retain unknown vsfalse/0.
}
//10 original collector,20 leaf and10 native-call control fixtures; native API and
//registry providers intercepted, names/arguments decoded from original code.
//No firmware/registry changes, sample/source execution or compilation.
}
