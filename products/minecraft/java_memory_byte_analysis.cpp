#include "java_memory_evidence_types.hpp"
#include <algorithm>
namespace ocean::reconstructed::minecraft_memory_evidence_review {
// Purpose: classify small memory samples using the recovered signatures and
// entropy thresholds. A suspicious classification is a heuristic input to the
// reporting stage, not a standalone identification of injected code.
// ibqyaELm@1c03240: Shannon byte entropy, including all zero/CC bytes.
double byte_entropy(Contracts &r, const Bytes &bytes) {
  if (bytes.empty())
    return 0;
  std::array<Word, 256> frequencies{};
  for (const auto b : bytes)
    ++frequencies[b];
  double result = 0;
  for (const auto n : frequencies)
    if (n > 0) {
      const double p = double(n) / double(bytes.size());
      result -= p * r.original_log2(p);
    }
  return result;
}
// Recovered (wu1alcKKb@1c03000): six exact nine-byte GS-read instruction
// patterns anywhere in the buffer.
bool contains_gs_pattern(const Bytes &bytes) {
  const std::array<std::array<std::uint8_t, 9>, 6> patterns{
      {{{0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0}},
       {{0x65, 0x48, 0x8b, 0x0c, 0x25, 0x60, 0, 0, 0}},
       {{0x65, 0x48, 0x8b, 0x14, 0x25, 0x60, 0, 0, 0}},
       {{0x65, 0x48, 0x8b, 0x1c, 0x25, 0x60, 0, 0, 0}},
       {{0x65, 0x4c, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0}},
       {{0x65, 0x4c, 0x8b, 0x0c, 0x25, 0x60, 0, 0, 0}}}};
  for (const auto &pattern : patterns)
    if (std::search(bytes.begin(), bytes.end(), pattern.begin(),
                    pattern.end()) != bytes.end())
      return true;
  return false;
}
// Recovered (grPdAsj_@1c02dc0): MZ only at the start; GS/syscall patterns
// anywhere. There is no PE parser, signature check or executable loader here.
bool suspicious_byte_content(Contracts &r, const Bytes &bytes) {
  if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z')
    return true;
  if (contains_gs_pattern(bytes))
    return true;
  for (std::size_t i = 0; i + 9 < bytes.size(); ++i)
    if (bytes[i] == 0x4c && bytes[i + 1] == 0x8b && bytes[i + 2] == 0xd1 &&
        bytes[i + 3] == 0xb8 && bytes[i + 8] == 0x0f && bytes[i + 9] == 0x05)
      return true; // four arbitrary immediate bytes
  std::size_t run = 0;
  for (const auto b : bytes) {
    run = b == 0x90 ? run + 1 : 0;
    if (run >= 64)
      return true;
  }
  if (bytes.size() >= 256) {
    const auto zeros = std::count(bytes.begin(), bytes.end(), std::uint8_t{0});
    if (double(zeros) / double(bytes.size()) < 0.15 &&
        byte_entropy(r, bytes) > 7.3)
      return true;
  }
  return false;
}
// Recovered (xOZmcR@1c02cc0): 0 = empty/padding, 1 = intermediate,
// 2 = suspicious.
int classify_bytes(Contracts &r, const Bytes &bytes) {
  if (bytes.empty())
    return 0;
  if (suspicious_byte_content(r, bytes))
    return 2;
  std::size_t substantive = 0;
  for (const auto b : bytes)
    if (b != 0 && b != 0xcc)
      ++substantive;
  if (substantive <= 7)
    return 0;
  if (substantive >= 2048)
    return 2;
  return 1;
}
// niS2Re_TFVig@1c01960. Empty/error -> nil slice; success -> full allocation.
Bytes read_up_to_page(Contracts &r, Word handle, Word address, Word size) {
  if (size == 0)
    return {};
  const auto length = std::min<Word>(size, 4096);
  Bytes bytes(length, 0);
  if (r.original_read_process_memory(handle, address, bytes).present())
    return {};
  return bytes;
}
// lG6668@1c00e20. At least 64 bytes; exactly 64 read; 62..64 zeros qualify.
bool mostly_zero_header(Contracts &r, Word handle, Word address, Word size) {
  if (size < 64)
    return false;
  Bytes bytes(64, 0);
  if (r.original_read_process_memory(handle, address, bytes).present())
    return false;
  return std::count(bytes.begin(), bytes.end(), std::uint8_t{0}) > 61;
}
// ifnH3tQLF@1c01020. Mapped executable region gets mdl without reading
// contents. Private RWX larger than 4096 gets DLLMap only for successful MZ.
bool mark_region(Contracts &r, Word handle, RegionEvidence &region) {
  if (region.mapped && (region.protection == 32 || region.protection == 64)) {
    region.label = "mdl";
    return true;
  }
  if (region.type == 0x20000 && region.protection == 64 && region.size > 4096) {
    Bytes bytes(2, 0);
    if (!r.original_read_process_memory(handle, region.base, bytes).present() &&
        bytes[0] == 'M' && bytes[1] == 'Z') {
      region.label = "DLLMap";
      return true;
    }
  }
  return false;
}
// Evidence: 81 original byte/header/reader paths, including the original
// entropy and math routines, with three modeled entropy-threshold values.
// Six original Log2 points returned, including non-power-of-two 0.1.
// Review text only; no native API/sample/reconstructed C++ executes.
} // namespace ocean::reconstructed::minecraft_memory_evidence_review
