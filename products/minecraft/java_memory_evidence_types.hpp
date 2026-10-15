#pragma once
#include "../../session/session_types.hpp"
#include <array>
#include <memory>
#include <unordered_map>
namespace ocean::reconstructed::minecraft_memory_evidence_review {
// Shared logical types for the Java process-memory heuristic. The scanner
// observes region metadata and up to one page of selected contents; it does
// not reconstruct or execute code found in the target process.
using Word = std::uint64_t;
using Bytes = std::vector<std::uint8_t>;
struct Error {
  Word type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct MemoryInformation {
  Word base = 0, allocation_base = 0, size = 0;
  std::uint32_t allocation_protection = 0, state = 0, protection = 0, type = 0;
};
// Original allocation row 3768d80:40 bytes. The final type word has padding.
struct AllocationRow {
  Word base = 0;
  std::uint32_t initial_protection = 0;
  Word size = 0;
  std::uint32_t state = 0, protection = 0, type = 0;
};
// Original committed row 378d200:64 bytes; booleans36/37/38, label40/48.
struct RegionEvidence {
  Word base = 0, allocation_base = 0, size = 0;
  std::uint32_t type = 0, protection = 0, state = 0;
  bool private_writable = false, mapped = false, marked = false;
  ByteString label;
  std::uint32_t previous_protection = 0; // last original DWORD60
};
// Original receiver 377f660:104 bytes. Word0 handle, slices8 and32,
// followed by six uint64 counters at56,64,72,80,88,96.
struct Scan {
  Word handle = 0;
  std::vector<RegionEvidence> regions;
  std::vector<AllocationRow> allocations;
  Word marked_regions = 0;
  Word reserve_after_free = 0;
  Word free_transitions = 0;
  Word uncommitted_regions = 0;
  Word mostly_zero_headers = 0;
  Word protection_changes = 0;
};
struct AllocationSummary {
  std::uint32_t initial_protection = 0;
  Word total = 0, executable = 0, noaccess = 0, reserved = 0;
  bool private_region = false, mapped_or_image = false;
}; // original37729a0:48 bytes
using AllocationMap = std::unordered_map<Word, AllocationSummary>;
struct Opened {
  Word handle = 0;
  Error error;
};
struct Contracts {
  virtual Opened original_open_process(std::uint32_t access, bool inherit,
                                       std::uint32_t) = 0;
  virtual Error original_close_handle(Word) = 0;
  virtual Error original_virtual_query(Word handle, Word address,
                                       MemoryInformation &,
                                       Word structure_size) = 0;
  // Destination is zero-initialized. Original callers pass nullptr for bytes
  // read and rely solely on the wrapper error result; no count validation.
  virtual Error original_read_process_memory(Word handle, Word address,
                                             Bytes &destination) = 0;
  virtual bool original_error_is_errno87(Error) = 0;
  virtual Error original_format_error_or_literal(const ByteString &, Error) = 0;
  virtual double original_log2(double) = 0; // math.kwtqBT@254760
  virtual void original_diagnostic_log(const ByteString &) = 0;
  virtual void append_debug(const ByteString &level, const ByteString &label,
                            GoInt count) = 0;
  virtual bool has_lowercase_jar_in_open_files(
      std::int32_t pid) = 0; // existing source: java_mod_inventory.cpp
};
double byte_entropy(Contracts &, const Bytes &);
bool suspicious_byte_content(Contracts &, const Bytes &);
int classify_bytes(Contracts &, const Bytes &);
Bytes read_up_to_page(Contracts &, Word handle, Word address, Word size);
bool mostly_zero_header(Contracts &, Word handle, Word address, Word size);
bool mark_region(Contracts &, Word handle, RegionEvidence &);
Error collect_memory_regions(Contracts &, Scan &);
AllocationMap summarize_allocations(const std::vector<AllocationRow> &);
GoInt count_small_private_rwx(Contracts &, const Scan &);
GoInt count_inaccessible_executable_allocations(const Scan &);
void report_memory_evidence(Contracts &, const Scan &, GoInt pid,
                            std::size_t selected_pid_count);
void check_selected_java_pids(Contracts &, const std::vector<GoInt> &);
// Review declarations only. No Windows/native bindings; never compiled/run.
} // namespace ocean::reconstructed::minecraft_memory_evidence_review
