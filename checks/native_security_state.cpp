#include "../../common/review_contracts.hpp"
#include <array>
// Recovered behavior summary:
//   Input: NtQuerySystemInformation class 103, SecureBoot UEFI byte, and HiberbootEnabled registry
//          DWORD.
//   Gate: Memory Integrity tests option bit 0x400; Secure Boot and Fast Boot require exact
//         byte/DWORD value 1.
//   Output: Returns typed Result<bool> values used by the shared security wrapper.
//   Failure: Native/UTF-16/type failures return explicit errors; successful registry opens retain
//            deferred close.

namespace ocean::reconstructed::native_security_success_review {
struct NativeReturn {
    std::uint64_t first,second;
    GoError last_error;
};
struct IntegrityBuffer {
    std::uint32_t length=8,options=0,returned_length=0;
};
struct FirmwareBuffer {
    std::uint8_t value=0;
};
struct RegistryDwordBuffer {
    std::uint32_t type=0,value=0,byte_length=4;
};
struct OpenKeyBuffer {std::uint64_t key=0;};
struct NativeSecurityContracts {
 virtual ~NativeSecurityContracts()=default;
 virtual Result<std::u16string> original_utf16_from_string(const ByteString&)=0;
 virtual NativeReturn original_nt_query_system_information(std::uint32_t info_class,IntegrityBuffer&,std::uint32_t byte_length)=0;
 virtual NativeReturn original_get_firmware_environment_variable(
  const std::u16string& name,const std::u16string& guid,
  FirmwareBuffer&,std::uint32_t buffer_size)=0;
 virtual NativeReturn original_reg_open_key_ex(
  std::uint64_t root,const std::u16string&,std::uint32_t options,
  std::uint32_t access,OpenKeyBuffer&)=0;
 virtual NativeReturn original_reg_query_value_ex(std::uint64_t key,const std::u16string&,RegistryDwordBuffer&)=0;
 virtual void original_register_deferred_reg_close_key(std::uint64_t key)=0;
 // Preserve original failure construction/ABI as contracts. Successful native
 // branches were fixture-tested; these failure paths need separate review.
 virtual GoError original_code_integrity_call_failure(const NativeReturn&)=0;
 virtual GoError original_firmware_call_failure(const NativeReturn&)=0;
 virtual GoError original_registry_open_failure(const NativeReturn&)=0;
 virtual GoError original_registry_query_failure(const NativeReturn&)=0;
 virtual GoError original_registry_wrong_type(std::uint32_t)=0;
};
// QoqhEaa@12b8040 -> ntdll!NtQuerySystemInformation global5728ea8.
// Input class103,8-byte buffer initialized length8; returned length lives in
// a separate uint32 immediately following it. Successful result tests bit10.
Result<bool> memory_integrity_state(NativeSecurityContracts& r) {
 IntegrityBuffer buffer;
 const auto result=r.original_nt_query_system_information(103,buffer,8);
 if(result.first!=0) return {false,r.original_code_integrity_call_failure(result)};
 return {(buffer.options&0x400)!=0,{0,0}};
}
// DbQgpg2dboX_@12b8320 -> kernel32!GetFirmwareEnvironmentVariableW
// global5728eb0. Actual name/GUID and one-byte buffer recovered from native
// arguments. Any nonzero returned length takes the byte==ONE branch.
Result<bool> secure_boot_state(NativeSecurityContracts& r) {
 const auto name=r.original_utf16_from_string("SecureBoot");
 if(name.error.present()) return {false,name.error};
 const auto guid=r.original_utf16_from_string("{8be4df61-93ca-11d2-aa0d-00e098032b8c}");
 if(guid.error.present()) return {false,guid.error};
 FirmwareBuffer buffer;
 const auto result=r.original_get_firmware_environment_variable(name.value,guid.value,buffer,1);
 if(result.first==0) return {false,r.original_firmware_call_failure(result)};
 return {buffer.value==1,{0,0}};
}
// PEwOG2vkzZa@12b9b00 -> uwIK0uC@12b85a0 and lRXafgTXJar@12b88c0.
// The first helper uses RegOpenKeyExW (options0/access1). The second makes
// one RegQueryValueExW call with initialized type0/value0/length4, rejects a
// successful result with type different from4, and returns its uint32 value.
// The root compares exactly1, and defers RegCloseKey after a successful open.
Result<bool> fast_boot_state(NativeSecurityContracts& r) {
 const auto path=r.original_utf16_from_string("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power");
 if(path.error.present()) return {false,path.error};
 OpenKeyBuffer key;
 const auto opened=r.original_reg_open_key_ex(0x80000002,path.value,0,1,key);
 if(opened.first!=0) return {false,r.original_registry_open_failure(opened)};
 r.original_register_deferred_reg_close_key(key.key);
 const auto value_name=r.original_utf16_from_string("HiberbootEnabled");
 if(value_name.error.present()) return {false,value_name.error};
 RegistryDwordBuffer buffer;
 const auto queried=r.original_reg_query_value_ex(key.key,value_name.value,buffer);
 if(queried.first!=0) return {false,r.original_registry_query_failure(queried)};
 if(buffer.type!=4) return {false,r.original_registry_wrong_type(buffer.type)};
 return {buffer.value==1,{0,0}};
}
// These helpers produce boolean check results. Their successful scalar values
// are not independently included in the upload by these bodies; the wrapper
// adds specific constant WARNINGS. Native API execution, privilege changes,
// firmware writes or registry writes are not implemented or performed here.
// Evidence:9 original instruction success fixtures (0,1,2), intercepted APIs,
// captured function bindings and original native-registry type-test body.
// Error construction, unusual returned lengths/types, syscall error conversion,
// UTF16 edge cases, defer/panic and privileges remain explicit limits.
// Review text only; never compiled or executed.
}
