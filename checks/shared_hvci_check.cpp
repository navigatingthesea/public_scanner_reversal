#include "../session/session_types.hpp"
#include <vector>
#include <optional>
#include <array>
#include <functional>
// Recovered behavior summary:
//   Input: Code Integrity registry/configuration values and the native Memory Integrity provider.
//   Gate: Applies the recovered exact registry and native-option comparisons that classify HVCI as
//         disabled or inconsistent.
//   Output: Emits the corresponding Memory Integrity warning/debug records.
//   Failure: Missing keys/values and native errors follow their individual no-finding branches; no
//            setting is changed.

namespace ocean::reconstructed::shared_hvci {
using Handle=std::uint64_t;
struct CodeIntegrity {
    bool enabled=false,query_ok=false;
};
struct Hypervisor {
    bool present=false;
    ByteString vendor;
};
struct RegistryState {
    bool opened=false,enabled_known=false,locked_known=false;
    std::uint32_t enabled=0,locked=0;
};
template<class T>struct Read {
    T value;
    bool error=false;
};
struct Cpuid {
    std::uint32_t eax=0,ebx=0,ecx=0,edx=0;
};
struct Contracts {
    virtual std::uint64_t nt_query_code_integrity(std::array<std::uint32_t,2>& buffer,std::uint64_t returned_length_pointer)=0;
    virtual Cpuid cpuid(std::uint32_t leaf)=0;
    virtual Read<Handle> open_hklm(const ByteString& path,std::uint32_t access)=0;
    virtual Read<std::uint64_t> integer_value(Handle,const ByteString& name)=0;
    virtual Read<std::vector<ByteString>> all_subkey_names(Handle)=0;
    virtual Read<ByteString> binary_value(Handle,const ByteString& name)=0;
    virtual void close_key_ignoring_error(Handle)=0;
    virtual void append_warning(const ByteString&)=0;
    virtual void append_debug(const std::vector<ByteString>&)=0;
    virtual void print_diagnostic(const CodeIntegrity&,const Hypervisor&,const RegistryState&,bool bcd_off)=0;
    virtual ByteString go_quote(const ByteString&)=0; //original fmt %q, not guessed JSON for arbitrary bytes
};
struct Close {std::function<void()> function;~Close(){function();}};
CodeIntegrity kernel_state(Contracts& rt){ //aq3iglJf0@129a4a0
    std::array<std::uint32_t,2> buffer{8,0};
    const auto status=rt.nt_query_code_integrity(buffer,0); //ntdll.dll!NtQuerySystemInformation(103,buffer,8,NULL)
    if(status!=0)return {};
    return {(buffer[1]&0x400)!=0,true}; //bit10; unlike test-driver check, nonzero NTSTATUS is rejected
}
Hypervisor hypervisor_state(Contracts& rt){ //sMX9Eg3rHG@129ab20
    if((rt.cpuid(1).ecx&0x80000000U)!=0)return {true,{}}; //early return omits vendor query
    const auto regs=rt.cpuid(0x40000000);
    ByteString vendor;
    for(auto word:{regs.ebx,regs.ecx,regs.edx})for(unsigned shift=0;shift<32;shift+=8)vendor.push_back(char(word>>shift));
    const auto trim=[](unsigned char c){return c==0 || c==' ';};
    while(!vendor.empty() && trim(vendor.front()))vendor.erase(vendor.begin());
    while(!vendor.empty() && trim(vendor.back()))vendor.pop_back();
    return {!vendor.empty(),vendor}; //nonempty vendor implies present even if leaf1 bit31 was clear
}
RegistryState registry_state(Contracts& rt){ //tBOakTmT0l1M@129ac20
    const auto key=rt.open_hklm("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",1);
    if(key.error)return {};
    Close close{[&]{rt.close_key_ignoring_error(key.value);}};
    const auto enabled=rt.integer_value(key.value,"Enabled");
    const auto locked=rt.integer_value(key.value,"Locked"); //read even after Enabled error
    return {true,!enabled.error,!locked.error,enabled.error?0:std::uint32_t(enabled.value),locked.error?0:std::uint32_t(locked.value)};
    //Registry type is ignored; successful values are narrowed to uint32.
}
bool any_bcd_hypervisor_off(Contracts& rt){ //tdyEmSfU9hq@129ada0
    const ByteString root="BCD00000000\\Objects";
    const auto key=rt.open_hklm(root,9);
    if(key.error)return false;
    Close close_root{[&]{rt.close_key_ignoring_error(key.value);}};
    const auto names=rt.all_subkey_names(key.value); //ReadSubKeyNames(-1)
    if(names.error)return false;
    for(const auto& name:names.value){
        const auto child=rt.open_hklm(root+"\\"+name+"\\Elements\\25000021",1);
        if(child.error)continue;
        Close close_child{[&]{rt.close_key_ignoring_error(child.value);}};
        const auto bytes=rt.binary_value(child.value,"Element");
        if(!bytes.error && !bytes.value.empty() && bytes.value[0]==0)return true;
    }
    return false;
    //Every enumerated BCD object is eligible, without selecting the current boot
    //object. Only first binary byte is tested; extra bytes and value type ignored.
}
void check(Contracts& rt){ //JX2VHFJJk@129c0c0
    const auto kernel=kernel_state(rt);
    const auto hypervisor=hypervisor_state(rt);
    const auto registry=registry_state(rt);
    const bool bcd_off=any_bcd_hypervisor_off(rt);
    rt.print_diagnostic(kernel,hypervisor,registry,bcd_off);
    //Exact diagnostic format:
    //kernel_hvci=%v query_ok=%v cpuid_hypervisor=%v vendor_leaf=%q reg_enabled=%v/%d locked=%v/%d bcd_off=%v
    if(kernel.query_ok && kernel.enabled && !hypervisor.present)
        rt.append_debug({"HVCI","spoof: kernel HVCI on without hypervisor","vendor_leaf="+rt.go_quote(hypervisor.vendor)});
    if(registry.locked_known && registry.locked==0)
        rt.append_debug({"HVCI","HVCI Locked=0 unlock trace"});
    if(bcd_off){
        if(!kernel.query_ok || !kernel.enabled){
            rt.append_warning(
                "Hypervisor Disabled [HVCI]:::Boot instance:::BCD hypervisorlaunchtype=off — "
                "the hypervisor is disabled at boot, so HVCI cannot be active");
            rt.append_debug({"HVCI","BCD hypervisorlaunchtype off"});
        }else rt.append_debug({"HVCI","BCD hypervisor off with kernel HVCI on"});
    }
    if(kernel.query_ok && !kernel.enabled && registry.opened && registry.enabled_known && registry.enabled==1){
        rt.append_warning(
            "HVCI State Mismatch [HVCI]:::Boot instance:::Registry Enabled=1 but kernel HVCI is inactive — "
            "hypervisor disabled behind the setting");
        rt.append_debug({"HVCI","registry enabled but kernel HVCI inactive"});
    }
    //Warnings are the app's interpretations of collected values. The BCD
    //enumerator alone does not establish the current boot configuration.
}
//31 original leaf routes and23 original whole-callback routes. Kernel native
//call, CPUID and registry providers synthetic; original string decoders/control
//flow interpreted in VM. C++ stays guest-only and is never compiled/executed.
}
