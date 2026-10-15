#include "java_memory_evidence_types.hpp"
namespace ocean::reconstructed::minecraft_memory_evidence_review {
// Purpose: enumerate a Java process's virtual-memory regions and derive the
// allocation groups consumed by the PRWX and FREE_REGIONS report checks.
bool executable_protection(std::uint32_t value) {
  return value == 16 || value == 32 || value == 64 || value == 128;
}
// ScanMemory@1c01140 appends to existing receiver collections/counters.
// Query error87 and address overflow are normal completion; other query
// errors return a formatted error while preserving already collected fields.
Error collect_memory_regions(Contracts &r, Scan &scan) {
  Word address = 0;
  std::uint32_t previous_state = 0, previous_protection = 0;
  for (;;) {
    MemoryInformation row;
    const auto error = r.original_virtual_query(scan.handle, address, row, 48);
    if (error.present())
      return r.original_error_is_errno87(error)
                 ? Error{}
                 : r.original_format_error_or_literal(
                       "error en VirtualQueryEx: %v", error);
    if (row.state == 0x1000 || row.state == 0x2000)
      scan.allocations.push_back({row.allocation_base,
                                  row.allocation_protection, row.size,
                                  row.state, row.protection, row.type});
    if (previous_protection != 0 && row.protection != previous_protection &&
        row.state == 0x1000)
      ++scan.protection_changes;
    // This helper receives the QUERY address, which is not replaced by
    // row.base.
    if (row.state == 0x1000 &&
        mostly_zero_header(r, scan.handle, address, row.size))
      ++scan.mostly_zero_headers;
    if (row.type != 0x1000000 && row.base > 0xffff && row.protection != 1) {
      if (row.state == 0x10000 && previous_state != 0x10000)
        ++scan.free_transitions;
      else if (row.state == 0x2000 && previous_state == 0x10000)
        ++scan.reserve_after_free;
      if (row.state != 0x1000)
        ++scan.uncommitted_regions;
    }
    if (row.state == 0x1000) {
      RegionEvidence evidence;
      evidence.base = row.base;
      evidence.allocation_base = row.allocation_base;
      evidence.size = row.size;
      evidence.type = row.type;
      evidence.protection = row.protection;
      evidence.state = row.state;
      evidence.private_writable =
          row.type == 0x20000 && (row.protection == 4 || row.protection == 64);
      evidence.mapped = row.type == 0x40000;
      evidence.previous_protection = previous_protection;
      evidence.marked = mark_region(r, scan.handle, evidence);
      if (evidence.marked)
        ++scan.marked_regions;
      scan.regions.push_back(evidence);
    }
    const auto next = row.base + row.size;
    if (next < row.base)
      return {};
    address = next;
    previous_state = row.state;
    previous_protection = row.protection;
  }
}
// wEwiDeYAHxsw@1c03380: group by exact nonzero allocation base. First
// allocation protection wins; sizes and category flags accumulate across rows.
AllocationMap summarize_allocations(const std::vector<AllocationRow> &rows) {
  AllocationMap result;
  for (const auto &row : rows) {
    if (row.base == 0)
      continue;
    auto found = result.find(row.base);
    if (found == result.end())
      found =
          result.emplace(row.base, AllocationSummary{row.initial_protection})
              .first;
    auto &group = found->second;
    group.total += row.size;
    if (row.type == 0x20000)
      group.private_region = true;
    else if (row.type == 0x40000 || row.type == 0x1000000)
      group.mapped_or_image = true;
    if (row.state == 0x1000) {
      const auto protect = row.protection & 0xbffff8ffU;
      if (protect == 1)
        group.noaccess += row.size;
      else if (executable_protection(protect))
        group.executable += row.size;
    } else if (row.state == 0x2000)
      group.reserved += row.size;
  }
  return result;
}
// Recovered (ryfEY7TU@1c01720): 1..4096-byte, private, committed, exact-RWX
// regions. Allocation stats may be absent. Existing stats exclude mapped/image,
// total>2MiB or executable>64KiB. Only byte classification2 is counted.
GoInt count_small_private_rwx(Contracts &r, const Scan &scan) {
  const auto groups = summarize_allocations(scan.allocations);
  GoInt count = 0;
  for (const auto &region : scan.regions) {
    if (region.type != 0x20000 || region.state != 0x1000 ||
        region.protection != 64 || region.size == 0 || region.size > 4096)
      continue;
    const auto group = groups.find(region.allocation_base);
    if (group != groups.end() &&
        (group->second.mapped_or_image || group->second.total > 2097152 ||
         group->second.executable > 65536))
      continue;
    if (classify_bytes(
            r, read_up_to_page(r, scan.handle, region.base, region.size)) == 2)
      ++count;
  }
  return count;
}
// Recovered (usmA3pATs@1c03560): count private allocations that began
// executable but are now entirely reserved/no-access. The draft decompiler
// omitted these conditions.
// The original machine loop and37 grouping/filter fixtures establish them.
GoInt count_inaccessible_executable_allocations(const Scan &scan) {
  const auto groups = summarize_allocations(scan.allocations);
  GoInt count = 0;
  for (const auto &item : groups) {
    const auto &group = item.second;
    if (!group.private_region || group.mapped_or_image ||
        !executable_protection(group.initial_protection & 0xbffff8ffU))
      continue;
    if (group.total < 65536 || group.total > 2097152 || group.executable != 0)
      continue;
    const auto inaccessible = group.noaccess + group.reserved;
    if (inaccessible != 0 && inaccessible == group.total)
      ++count;
  }
  return count;
}
// 14 complete scanner paths and15 private-RWX counter paths returned.
// Memory counters above are collected even where PrintResults does not use
// them; no extra upload/serialization of those counters is inferred here.
// Native API/error/map/runtime behavior remains declared in Contracts.
// Review text only; never compiled or executed.
} // namespace ocean::reconstructed::minecraft_memory_evidence_review
