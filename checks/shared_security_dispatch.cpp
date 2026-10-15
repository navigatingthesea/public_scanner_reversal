#include "../../common/review_contracts.hpp"
#include <array>
// Recovered behavior summary:
//   Input: The shared-check callback table and its runtime scheduling/reporting providers.
//   Gate: Invokes callbacks in the recovered registration/order and preserves each callback
//         boundary.
//   Output: Coordinates shared security findings without adding new detector predicates.
//   Failure: Per-callback timing/recovery and missing provider behavior remain explicit contracts.

namespace ocean::reconstructed::shared_security_review {
struct NamedCheck {
    const char* label;
    std::uint64_t callback_rva;
};
// vJtYm8.DPFY8kTv@1797980. Original43 named jobs in table order.
// Internal labels identify callbacks; deeper check semantics stay explicit.
constexpr std::array<NamedCheck,43> checks={{
 {"PcaBypass",0x12a24e0}, //PEhVuBqkg8Zt.ZlDbsI9
 {"NetBypass",0x125dce0}, //PEhVuBqkg8Zt.QVUohz43oK
 {"PrefetchBypass",0x12a8c80}, //PEhVuBqkg8Zt.A7r0EG7c95jA
 {"CommandProcessor",0x125df80}, //PEhVuBqkg8Zt.Yz45iqrL
 {"ActivitiesCache",0x125aee0}, //PEhVuBqkg8Zt.AAcXOJQI1iy
 {"TypeBypass",0x12c6060}, //PEhVuBqkg8Zt.HwHNxT
 {"Unicode",0x12c72a0}, //PEhVuBqkg8Zt.Hy8IIwrH5f
 {"PY",0x12acc80}, //PEhVuBqkg8Zt.PaNxJEswSLgI
 {"Powershell",0x12a7e80}, //PEhVuBqkg8Zt.Oap2StG4
 {"TaskSchedule",0x12c4760}, //PEhVuBqkg8Zt.VU3hi3tAy
 {"TaskSchedule2",0x12c24c0}, //PEhVuBqkg8Zt.OWIYTd
 {"EfiBoot",0x1283b40}, //PEhVuBqkg8Zt.GfPkPdJEPPRE
 {"HvciSpoof",0x129c0c0}, //PEhVuBqkg8Zt.JX2VHFJJk
 {"VirtualDisk",0x12ca220}, //PEhVuBqkg8Zt.F30AdMWzt4Bt
 {"USB",0x12c9120}, //PEhVuBqkg8Zt.OobnwSELL_
 {"FactoryReset",0x129d300}, //PEhVuBqkg8Zt.AOqeamxFbv_7
 {"CheckUSN",0x12c9620}, //PEhVuBqkg8Zt.OcgNuIK9YVq
 {"UnicodeDrive",0x12c78a0}, //PEhVuBqkg8Zt.ROnqY1
 {"DBypass",0x1263920}, //PEhVuBqkg8Zt.IMxu1zUTJ
 {"RServices",0x12d1e80}, //PEhVuBqkg8Zt.TiPMEA
 {"RServices2",0x12d5920}, //PEhVuBqkg8Zt.AbKf7uFX6z
 {"CheckEventlogIntegrity",0x1296880}, //PEhVuBqkg8Zt.JemWGP_E7G5
 {"FormatUSB",0x1299640}, //PEhVuBqkg8Zt.DRnPpFt2U
 {"FakeSignatures",0x1297a40}, //PEhVuBqkg8Zt.MhijPx
 {"Services_Permissions",0x12be3c0}, //PEhVuBqkg8Zt.BPLpHaZKQz1
 {"Drives",0x12647e0}, //PEhVuBqkg8Zt.Svd7H_7oO
 {"Tamper",0x12c1420}, //PEhVuBqkg8Zt.A7Ey7axB
 {"SysMainFilePatch",0x12609e0}, //PEhVuBqkg8Zt.ACpZILF
 {"NTTraceEvent",0x12613a0}, //PEhVuBqkg8Zt.LWpP9T3HE9
 {"ShadowPlay FTS DXGI",0x12c02c0}, //PEhVuBqkg8Zt.XNbiSvU
 {"CURL",0x125e360}, //PEhVuBqkg8Zt.BtZwlj2GWfu
 {"READONLY",0x12af520}, //PEhVuBqkg8Zt.HuwaqX7
 {"Journal",0x129f400}, //PEhVuBqkg8Zt.Iyvu7IhhPRo
 {"SigKid",0x12c0d00}, //PEhVuBqkg8Zt.Tm8_b5I
 {"EVTXBypass",0x12a05c0}, //PEhVuBqkg8Zt.N8huiY7Y
 {"J500",0x12a1c40}, //PEhVuBqkg8Zt.AksJRJEgQR
 {"PrivazerRegistry",0x12ab880}, //PEhVuBqkg8Zt.BRZj0zWRfVkD
 {"PrivazerPrefetch",0x12ac420}, //PEhVuBqkg8Zt.CHFR1G8oI6dJ
 {"Revo Uninstaller",0x12b13c0}, //PEhVuBqkg8Zt.A78aZiS2u
 {"EventLog Disabler",0x1294000}, //PEhVuBqkg8Zt.PDTUOfU
 {"SchtasksTransientChain",0x12b4180}, //PEhVuBqkg8Zt.BdZUamO
 {"Security Features",0x12b9fc0}, //PEhVuBqkg8Zt.XYFnooAj9
 {"BAM_2",0x125b180}, //PEhVuBqkg8Zt.TFi33xK7SYA
}};
struct SecurityDispatchContracts {
 virtual ~SecurityDispatchContracts()=default;
 virtual std::uint64_t original_allocate_waitgroup()=0;
 virtual void original_waitgroup_add(std::uint64_t,std::int64_t)=0;
 virtual void original_schedule_named_wrapper(std::uint64_t group,const NamedCheck&)=0;
 virtual void original_schedule_additional_worker(std::uint64_t group)=0; //DPFY8kTv.func34
 virtual void original_waitgroup_wait(std::uint64_t)=0;
 virtual void original_timed_recovery_scope(const std::function<void()>&)=0;
};
void dispatch_shared_security_checks(SecurityDispatchContracts& r) {
 r.original_timed_recovery_scope([&] {
  const auto group=r.original_allocate_waitgroup();
  for(const auto& check:checks) {
   r.original_waitgroup_add(group,1);
   r.original_schedule_named_wrapper(group,check);
  }
  r.original_waitgroup_add(group,1);
  r.original_schedule_additional_worker(group);
  r.original_waitgroup_wait(group);
 });
}
// Each original named wrapper registers deferred WaitGroup.Done and invokes
// its callback via the captured function value. Original timing/logger/panic
// recovery are retained as contracts; no sequential order between jobs is
// asserted. Evidence: shared-security-dispatcher-review.json.
// Review text only; never compiled or executed.
}
