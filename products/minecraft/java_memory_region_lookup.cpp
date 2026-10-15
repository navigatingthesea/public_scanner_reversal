#include "../../session/session_types.hpp"
#include <optional>
#include <vector>
namespace ocean::reconstructed::minecraft_java_regions {
// Purpose: locate an address in the process-region cache used by native-method
// classification. The two cached arrays are assumed to correspond by index.
using Address = std::uint64_t;
struct Region {
  Address base = 0, size = 0;
};
struct CachedProcessRegions {
  std::vector<Region> records; // process8 slice, length16; 16-byte records
  std::vector<Address> sorted_bases; // process32 slice, length40; 8-byte
                                     // entries
};
struct Contracts {
  [[noreturn]] virtual void panic_region_index() = 0;
};
std::optional<std::size_t>
containing_region(Contracts &rt, const CachedProcessRegions &cache,
                  Address address) { // cZkEv_@1a8ce40
  std::size_t low = 0, high = cache.sorted_bases.size();
  while (low < high) {
    const auto middle = (low + high) >> 1;
    if (middle >= cache.sorted_bases.size())
      rt.panic_region_index();
    if (cache.sorted_bases[middle] <= address)
      low = middle + 1;
    else
      high = middle;
  }
  if (low == 0)
    return std::nullopt;
  const auto index = low - 1;
  if (index >= cache.records.size())
    rt.panic_region_index();
  const auto &region = cache.records[index];
  if (region.base + region.size <= address)
    return std::nullopt;
  return index;
  // Chooses only the last base<=address, then checks its exclusive end. It
  // does not search earlier overlapping regions if the selected one ends too
  // soon. End arithmetic wraps; order/correspondence of cached arrays is
  // trusted.
}
// Evidence: 14 original fixtures: 13 returns and one bounds panic for
// mismatched cached-array lengths. Synthetic cached regions only; no process
// queries or execution.
} // namespace ocean::reconstructed::minecraft_java_regions
