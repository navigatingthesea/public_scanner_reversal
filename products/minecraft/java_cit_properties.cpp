#include "../../session/session_types.hpp"
#include <algorithm>
#include <optional>
#include <set>
namespace ocean::reconstructed::minecraft_cit_property_review {
// Purpose: detect OptiFine/MCPatcher CIT rules that select armor textures by
// damage or durability. Qualification requires one item to accumulate more
// than one distinct damage token; it does not verify numeric ranges or images.
// Go Unicode operations, provider I/O, and map iteration remain contracts.
struct PropertyResult {
  std::vector<ByteString> items, damage_tokens;
};
struct CITRecord {
  ByteString pack_name;
  std::vector<ByteString> items, property_paths;
};
struct Accumulator {
  ByteString pack_name;
  std::map<ByteString, std::set<ByteString>> damage_tokens_by_item;
  std::map<ByteString, std::vector<ByteString>> property_paths_by_item;
  GoInt processed_nonempty_files = 0;
};
struct ReadResult {
  ByteString bytes;
  bool has_error = false;
};
struct ZipMember {
  ByteString original_name;
  std::uint64_t uncompressed_size = 0;
};
struct CITContracts {
  virtual ByteString original_lower_utf8(const ByteString &) = 0;
  virtual ByteString original_trim_unicode_space(const ByteString &) = 0;
  virtual std::vector<ByteString>
  original_fields_unicode_space(const ByteString &) = 0;
  virtual bool original_equal_fold(const ByteString &, const ByteString &) = 0;
  virtual ReadResult original_zip_open_limit_read_all_close(const ZipMember &,
                                                            GoInt limit) = 0;
  virtual ReadResult original_read_whole_file(const ByteString &full_path) = 0;
  // Go map iteration is unspecified. It affects which eight property paths
  // survive the final global cap; item names themselves are sorted afterward.
  virtual std::vector<ByteString>
  original_item_iteration_order(const Accumulator &) = 0;
};
using ItemAliases = std::map<ByteString, ByteString>;
// Recovered: all 51 entries from global5728f00, type3639e00. This is the
// captured table, not a proof that server/session/init paths can never modify
// it.
ItemAliases captured_item_aliases() {
  return {
      {"298", "leather_helmet"},
      {"299", "leather_chestplate"},
      {"300", "leather_leggings"},
      {"301", "leather_boots"},
      {"302", "chainmail_helmet"},
      {"303", "chainmail_chestplate"},
      {"304", "chainmail_leggings"},
      {"305", "chainmail_boots"},
      {"306", "iron_helmet"},
      {"307", "iron_chestplate"},
      {"308", "iron_leggings"},
      {"309", "iron_boots"},
      {"310", "diamond_helmet"},
      {"311", "diamond_chestplate"},
      {"312", "diamond_leggings"},
      {"313", "diamond_boots"},
      {"314", "golden_helmet"},
      {"315", "golden_chestplate"},
      {"316", "golden_leggings"},
      {"317", "golden_boots"},
      {"443", "elytra"},
      {"chainmail_boots", "chainmail_boots"},
      {"chainmail_chestplate", "chainmail_chestplate"},
      {"chainmail_helmet", "chainmail_helmet"},
      {"chainmail_leggings", "chainmail_leggings"},
      {"diamond_boots", "diamond_boots"},
      {"diamond_chestplate", "diamond_chestplate"},
      {"diamond_helmet", "diamond_helmet"},
      {"diamond_leggings", "diamond_leggings"},
      {"elytra", "elytra"},
      {"gold_boots", "golden_boots"},
      {"gold_chestplate", "golden_chestplate"},
      {"gold_helmet", "golden_helmet"},
      {"gold_leggings", "golden_leggings"},
      {"golden_boots", "golden_boots"},
      {"golden_chestplate", "golden_chestplate"},
      {"golden_helmet", "golden_helmet"},
      {"golden_leggings", "golden_leggings"},
      {"iron_boots", "iron_boots"},
      {"iron_chestplate", "iron_chestplate"},
      {"iron_helmet", "iron_helmet"},
      {"iron_leggings", "iron_leggings"},
      {"leather_boots", "leather_boots"},
      {"leather_chestplate", "leather_chestplate"},
      {"leather_helmet", "leather_helmet"},
      {"leather_leggings", "leather_leggings"},
      {"netherite_boots", "netherite_boots"},
      {"netherite_chestplate", "netherite_chestplate"},
      {"netherite_helmet", "netherite_helmet"},
      {"netherite_leggings", "netherite_leggings"},
      {"turtle_helmet", "turtle_helmet"},
  };
}
ByteString trim_ascii_space_tab(const ByteString &s) {
  const auto first = s.find_first_not_of(" \t");
  if (first == ByteString::npos)
    return {};
  const auto last = s.find_last_not_of(" \t");
  return s.substr(first, last - first + 1);
}
ByteString normalize_slashes(ByteString s) {
  std::replace(s.begin(), s.end(), '\\', '/');
  return s;
}
std::vector<ByteString> comma_fields_unique(CITContracts &r, ByteString s) {
  std::replace(s.begin(), s.end(), ',', ' ');
  std::set<ByteString> seen;
  std::vector<ByteString> out;
  for (const auto &token : r.original_fields_unicode_space(s))
    if (seen.insert(token).second)
      out.push_back(token);
  return out;
}
// fVjjidiv6C5@1bf18c0. Byte substring match, no canonicalization, path
// component validation or requirement for an assets/minecraft prefix.
bool property_path_matches(CITContracts &r, const ByteString &original_path) {
  if (original_path.size() <= 15 ||
      !r.original_equal_fold(original_path.substr(original_path.size() - 11),
                             ".properties"))
    return false;
  const auto normalized =
      r.original_lower_utf8(normalize_slashes(original_path));
  return normalized.find("mcpatcher/cit/") != ByteString::npos ||
         normalized.find("optifine/cit/") != ByteString::npos;
}
// Recovered (dWCLagFb@1bf2260 + e67@1bf3500, zlc@1bf3780,
// kU@1bf3880):
// This is a small custom parser: '=' only; no Java-properties escapes or
// continuation handling; raw line-start #/! comments only. Damage tokens are
// strings: no numeric/range validity, color/image verification or numeric sort.
PropertyResult parse_properties(CITContracts &r, ByteString bytes,
                                const ItemAliases &aliases) {
  if (bytes.size() >= 3 && bytes.compare(0, 3, "\xef\xbb\xbf") == 0)
    bytes.erase(0, 3);
  ByteString type, item_text, damage_text;
  std::size_t start = 0;
  for (std::size_t end = 0; end <= bytes.size(); ++end) {
    if (end != bytes.size() && bytes[end] != '\n')
      continue;
    auto line = bytes.substr(start, end - start);
    start = end + 1;
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty() || line[0] == '#' || line[0] == '!')
      continue;
    const auto equal = line.find('=');
    if (equal == ByteString::npos || equal == 0)
      continue;
    const auto key =
        r.original_lower_utf8(trim_ascii_space_tab(line.substr(0, equal)));
    const auto value = trim_ascii_space_tab(line.substr(equal + 1));
    if (key == "type")
      type = r.original_lower_utf8(value);
    else if (key == "items" || key == "matchitems")
      item_text = value; // last assignment wins
    else if (key == "damage" || key == "damagepercent") {
      if (!damage_text.empty())
        damage_text += ' ';
      damage_text += value; // accumulated, not last-wins
    }
  }
  if (damage_text.empty())
    return {};
  const bool armor_type = type == "armor" || type == "elytra";
  if (!armor_type && !type.empty() && type != "item")
    return {};
  PropertyResult out;
  std::set<ByteString> seen_items;
  for (const auto &original : comma_fields_unique(r, item_text)) {
    auto normalized =
        r.original_lower_utf8(r.original_trim_unicode_space(original));
    if (normalized.compare(0, 10, "minecraft:") == 0)
      normalized.erase(0, 10);
    const auto found = aliases.find(normalized);
    ByteString item;
    if (found != aliases.end())
      item = found->second;
    if (item.empty() && armor_type)
      item = "armor:" + normalized;
    if (!item.empty() && seen_items.insert(item).second)
      out.items.push_back(item);
  }
  if (out.items.empty()) {
    if (!armor_type)
      return {};
    out.items.push_back("type_armor");
  }
  out.damage_tokens =
      comma_fields_unique(r, r.original_lower_utf8(damage_text));
  return out;
}
// cjIndqWM4@1bf1000. Path strings can repeat here. Tokens are unique per
// item across the whole pack. One file with two distinct tokens can qualify.
void accumulate(CITContracts &r, Accumulator *a, const ByteString &path,
                const ByteString &bytes, const ItemAliases &aliases) {
  if (!a || bytes.empty())
    return;
  const auto parsed = parse_properties(r, bytes, aliases);
  if (parsed.items.empty() || parsed.damage_tokens.empty())
    return;
  const auto normalized = normalize_slashes(path);
  for (const auto &item : parsed.items) {
    auto &variants = a->damage_tokens_by_item[item];
    variants.insert(parsed.damage_tokens.begin(), parsed.damage_tokens.end());
    auto &paths = a->property_paths_by_item[item];
    if (paths.size() < 8)
      paths.push_back(normalized);
  }
}
// xJ68l_@1bf1380. More than one distinct token is the actual item gate.
// No requirement for two files, disjoint valid ranges or different textures.
std::optional<CITRecord> finalize(CITContracts &r, const Accumulator &a) {
  CITRecord out{a.pack_name, {}, {}};
  std::set<ByteString> seen_paths;
  for (const auto &item : r.original_item_iteration_order(a)) {
    const auto found = a.damage_tokens_by_item.find(item);
    if (found == a.damage_tokens_by_item.end() || found->second.size() <= 1)
      continue;
    out.items.push_back(item);
    const auto paths = a.property_paths_by_item.find(item);
    if (paths == a.property_paths_by_item.end())
      continue;
    for (const auto &path : paths->second) {
      if (seen_paths.count(path))
        continue;
      if (out.property_paths.size() >= 8)
        break;
      seen_paths.insert(path);
      out.property_paths.push_back(path);
    }
  }
  if (out.items.empty())
    return std::nullopt;
  std::sort(out.items.begin(), out.items.end());
  return out;
}
// _NqY26U@1bf1d20. Full 64-bit size gate; the original decompiler's '(uint)'
// was misleading. Count advances on successful nonempty read BEFORE parsing,
// including property files which produce no recognized item/damage record.
std::optional<CITRecord>
inspect_zip(CITContracts &r, const std::vector<const ZipMember *> &members,
            const ByteString &pack_name, const ItemAliases &aliases) {
  Accumulator a;
  a.pack_name = pack_name;
  for (const auto *member : members) {
    if (a.processed_nonempty_files >= 256)
      break;
    if (!member || member->uncompressed_size == 0 ||
        member->uncompressed_size > 16384 ||
        !property_path_matches(r, member->original_name))
      continue;
    const auto read = r.original_zip_open_limit_read_all_close(*member, 16384);
    if (read.has_error || read.bytes.empty())
      continue;
    ++a.processed_nonempty_files;
    accumulate(r, &a, member->original_name, read.bytes, aliases);
  }
  return finalize(r, a);
}
// aqSdZ3UBNe_@1bf2140, called by rSwmhRCxh.func3 for non-directory
// entries with no walk callback error. Size is FileInfo.Size(), relative path
// is filepath.Rel(pack root,full path). Full-file ReadFile precedes truncation.
void inspect_directory_file(CITContracts &r, Accumulator *a,
                            const ByteString &relative,
                            const ByteString &full_path, GoInt metadata_size,
                            const ItemAliases &aliases) {
  if (!a || metadata_size < 1 || metadata_size > 16384 ||
      a->processed_nonempty_files >= 256 || !property_path_matches(r, relative))
    return;
  auto read = r.original_read_whole_file(full_path);
  if (read.has_error || read.bytes.empty())
    return;
  ++a->processed_nonempty_files;
  if (read.bytes.size() > 16384)
    read.bytes.resize(16384);
  accumulate(r, a, relative, read.bytes, aliases);
}
// Unresolved/provider boundary: root walking, native FileInfo behavior, ZIP
// decompression, and the icon/metadata pipeline are reconstructed elsewhere.
// concurrent result order and error/panic recovery are reviewed separately.
// Final record maps to JavaCITDurability: pack_name,comma-joined items,
// comma-joined property_paths. Damage token values are not included there.
} // namespace ocean::reconstructed::minecraft_cit_property_review
