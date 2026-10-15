#pragma once
#include "../../common/review_contracts.hpp"
#include <array>
#include <vector>

namespace ocean::reconstructed::lua_review {
struct Binding {
    const char* name;
    std::uint64_t bridge_rva;
    std::uint64_t callback_rva;
    const char* capture;
};

// Recovered: all 38 function registrations reached by the installation chain.
// Names identify the exposed API; they do not by themselves prove callback behavior.
inline constexpr std::array<Binding, 38> application_bindings = {{
    {"json.decode", 0x1f16360, 0x1f1e700, "static Go function descriptor"},
    {"json.encode", 0x1f161c0, 0x1f1e7c0, "static Go function descriptor"},
    {"print", 0x1f15e40, 0x1f15fe0, "report callback"},
    {"oprint", 0x1f159e0, 0x1f15b80, "report callback"},
    {"firstbytes", 0x1f15840, 0x1f1ee80, "static Go function descriptor"},
    {"drives", 0x1f156a0, 0x1f1ef80, "static Go function descriptor"},
    {"journal", 0x1f15500, 0x1f1f020, "static Go function descriptor"},
    {"time", 0x1f15360, 0x1f1f0e0, "static Go function descriptor"},
    {"boottime", 0x1f151c0, 0x1f1f1a0, "static Go function descriptor"},
    {"flag", 0x1f14f40, 0x1f150e0, "per-rule flag map"},
    {"IsPe", 0x1f14da0, 0x1f20300, "static Go function descriptor"},
    {"PeFile", 0x1f14c00, 0x1f203c0, "static Go function descriptor"},
    {"get", 0x1f14a60, 0x1f20480, "static Go function descriptor"},
    {"GetFiles", 0x1f148c0, 0x1f20540, "static Go function descriptor"},
    {"ParsePrefetch", 0x1f14720, 0x1f22620, "static Go function descriptor"},
    {"ReadRegKey", 0x1f14580, 0x1f23340, "static Go function descriptor"},
    {"readpmem", 0x1f143e0, 0x1f24060, "static Go function descriptor"},
    {"ReadEventLog", 0x1eeb7c0, 0x1f37c00, "static Go function descriptor"},
    {"ListEventLogs", 0x1eeb620, 0x1f391a0, "static Go function descriptor"},
    {"Processes", 0x1eeb480, 0x1f39e40, "static Go function descriptor"},
    {"Services", 0x1eeb2e0, 0x1f3ae60, "static Go function descriptor"},
    {"InstalledSoftware", 0x1eeb140, 0x1f3be00, "static Go function descriptor"},
    {"Users", 0x1eeafa0, 0x1f3c980, "static Go function descriptor"},
    {"Connections", 0x1eeae00, 0x1f3d000, "static Go function descriptor"},
    {"SmbConnections", 0x1eeac60, 0x1f3eaa0, "static Go function descriptor"},
    {"ListSmbShares", 0x1eeaac0, 0x1f3eca0, "static Go function descriptor"},
    {"HostInfo", 0x1eea920, 0x1f3ffa0, "static Go function descriptor"},
    {"FileInfo", 0x1eea780, 0x1f40b60, "static Go function descriptor"},
    {"HashFile", 0x1eea5e0, 0x1f42740, "static Go function descriptor"},
    {"FindFiles", 0x1eea440, 0x1f446a0, "static Go function descriptor"},
    {"ListRegKeys", 0x1eea2a0, 0x1f46de0, "static Go function descriptor"},
    {"result", 0x1ef30e0, 0x1f33680, "static Go function descriptor"},
    {"log", 0x1ef2cc0, 0x1ef2e60, "static Go function descriptor"},
    {"lastWrite", 0x1ef2b20, 0x1f360a0, "static Go function descriptor"},
    {"createdAt", 0x1ef2980, 0x1f36160, "static Go function descriptor"},
    {"FindString", 0x1ef27e0, 0x1ef3280, "static Go function descriptor"},
    {"MemStrings", 0x1ef2640, 0x1f36300, "static Go function descriptor"},
    {"ScanPattern", 0x1ef24a0, 0x1f36bc0, "static Go function descriptor"},
}};

inline constexpr std::array<const char*, 8> disabled_globals = {
    "load", "loadfile", "dofile", "require", "io", "os", "debug", "package",
};

// Recovered bootstrap: these four string helpers return only whether the first
// original string.find result is non-nil. Match captures, indexes, iterators, and
// replacement behavior are discarded.
inline constexpr const char bootstrap_script[] = R"OCEAN_LUA(
local find = string.find
string.find = function(s, pattern, init, plain)
	local at = find(s, pattern, init, plain)
	return at ~= nil
end
string.match = function(s, pattern, init)
	local at = find(s, pattern, init)
	return at ~= nil
end
string.gmatch = function(s, pattern)
	local at = find(s, pattern)
	return at ~= nil
end
string.gsub = function(s, pattern)
	local at = find(s, pattern)
	return at ~= nil
end
)OCEAN_LUA";
}
