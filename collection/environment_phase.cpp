#include "../lua/query_records.hpp"
#include <optional>
namespace ocean::reconstructed::collection_review {
// Recovered: this controller runs the environment collectors in fixed order and
// copies their results into payload globals. Provider-specific failure sentinels
// are preserved; a zero cached reference time does not overwrite prior time data.
using ByteString = lua_review::ByteString;
using GoTimeWords = lua_review::GoTimeWords;
// Names reflect their verified outgoing payload labels, not inferred provider algorithms.
struct EnvironmentGlobals {
    ByteString country;              // 572b920/928 ->COUNTRY, GoFq mapsite1f05332
    ByteString vpn;                  // 572b980/988 ->VPN, mapsite1f052b8
    ByteString boot_duration;        // 572b930/938 ->BOOT_TIME
    ByteString recycle_bin;          // 572b950/958 ->RECYCLE_BIN
    ByteString screenshot;           // 572b940/948 ->SCREENSHOT
    ByteString windows_version;      // 572b820/828 ->WINDOWS_VERSION
    ByteString install_date;         // 572b960/968 ->InstallDate
    ByteString factory_reset;        // 572b970/978 ->factory_reset
    ByteString factory_reset_mirror; // 572c830/838
    std::optional<std::vector<std::uint8_t>> discord_scope_json; // 572e300/308/310
    GoTimeWords game_start_time; // 572efa0/fa8/fb0; different from formatted GAME_TIME572b990/998
};
struct EnvironmentPhaseContracts {
    struct CountryVpn {
        ByteString country, vpn;
    };
    virtual ~EnvironmentPhaseContracts() = default;
    virtual void update_progress(std::int64_t) = 0;   // CnZChe3sX, ignored returned error
    virtual CountryVpn collect_country_vpn() = 0;     // RrWgjNW @f2ffa0, AX/BX then CX/DI
    virtual ByteString collect_boot_duration() = 0;   // PeQpKOaSd @f38180
    virtual ByteString collect_recycle_bin() = 0;     // JGiouZSfFiu @f19c00
    virtual ByteString collect_screenshot() = 0;      // U6gAnnRITV @f343a0
    virtual ByteString collect_windows_version() = 0; // HNibUJO5KT @f38780
    virtual ByteString collect_install_date() = 0;    // WFAUCwhce_f @f24a40
    virtual ByteString collect_factory_reset() = 0;   // RmPZxSKPcklB @f26520
    virtual std::optional<std::vector<std::uint8_t>>
    collect_discord_scope_json() = 0; // Id4KMAaH @f1f740
    virtual GoTimeWords
    collect_cached_install_reference_time() = 0; // EeB6Y7KK_@f273e0, source-description string
                                                 // discarded
    // These original no-argument calls can affect other globals; context is supplied
    // for reviewing those effects, not asserted to be their Go argument ABI.
    virtual void original_hook(std::uint32_t rva, EnvironmentGlobals &) = 0;
};
// Original contiguous controller phase@1efc29d..1efc4aa, before progress10.
void collect_environment_phase(EnvironmentPhaseContracts &r, EnvironmentGlobals &globals) {
    r.update_progress(5);
    const auto location = r.collect_country_vpn();
    globals.country = location.country;
    globals.vpn = location.vpn;
    globals.boot_duration = r.collect_boot_duration();
    globals.recycle_bin = r.collect_recycle_bin();
    globals.screenshot = r.collect_screenshot();
    globals.windows_version = r.collect_windows_version();
    globals.install_date = r.collect_install_date();
    globals.factory_reset = r.collect_factory_reset();
    globals.factory_reset_mirror = globals.factory_reset;
    globals.discord_scope_json = r.collect_discord_scope_json();
    r.original_hook(0xe2a900,
                    globals); // Windows InstallDate seed +PID append: game_time_fallback.cpp
    const auto game_start = r.collect_cached_install_reference_time();
    if (game_start.wall != 0 || game_start.ext != 0)
        globals.game_start_time = game_start;
    // A zero time leaves ALL previous time fields, including location, unchanged.
    r.original_hook(0x10ac7e0, globals); // numeric cached-response worker: numeric_cache_worker.cpp
    r.original_hook(0xf23840,
                    globals); // hashed service/process-name table: hashed_name_inventory.cpp
}
} // namespace ocean::reconstructed::collection_review
