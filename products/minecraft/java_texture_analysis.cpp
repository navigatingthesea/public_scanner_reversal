// Inferred captured nested JSON keys (type375d120, no tags/custom marshal):
// block name PW0V6RSo; transparency OxwEQY; darkness ZkcjdrNXlTbm;
// suspicious DDVKFei; reason GvX37QMetX7A. Logical C++ names differ.
// Scalar provenance now reviewed in java_resourcepack_metadata.cpp: shared
// metadata field at offset 56 is the last successfully read pack.png-substring
// ZIP member Header field at offset 76 (CRC32 layout inference), reused for
// every filename blacklist call. Folder metadata forces it to zero; it is not
// each file's CRC.
#include "../../session/session_types.hpp"
#include <array>
namespace ocean::reconstructed::minecraft_texture_review {
// Purpose: score resource packs for X-ray-like textures using transparency,
// darkness, repeated transparent-line patterns, filenames, and four captured
// CRC constants. The result is heuristic and limited to 19 target textures.
struct AnalyzerConfig {
  double transparency_threshold = 0.3, dark_threshold = 0.8;
  std::vector<ByteString> texture_names;
};
struct Rectangle {
  GoInt min_x, min_y, max_x, max_y;
};
struct RGBA16 {
  std::uint32_t r, g, b, a;
};
struct ImageReview {
  std::uint64_t original_itab, original_data;
};
struct TextureResult {
  ByteString name;
  double transparency = 0, darkness = 0;
  bool suspicious = false;
  ByteString reason;
};
struct PackResult {
  ByteString name, path, logo;
  bool is_xray = false;
  ByteString detection_method;
  std::vector<TextureResult> suspicious_blocks;
  double score = 0;
  GoInt analyzed_blocks = 0, total_blocks = 0;
  std::vector<ByteString> blacklisted_files;
}; // 144-byte original37848a0 JSON tags PackName/PackPath/Logo/IsXRay/
   // DetectionMethod/SuspiciousBlocks/OverallScore/AnalyzedBlocks/TotalBlocks/BlacklistedFiles.
struct ZipEntryReview {
  ByteString name;
  std::uint64_t original_pointer;
};
struct TextureContracts : TextContracts {
  virtual ByteString windows_base(const ByteString &) = 0;
  virtual Result<std::vector<ZipEntryReview>>
  original_open_zip_directory(const ByteString &) = 0;
  virtual void original_defer_archive_close() = 0;
  virtual Result<ImageReview>
  original_zip_member_readall_decode_image(const ZipEntryReview &) = 0;
  virtual Rectangle original_image_bounds(ImageReview) = 0;
  virtual RGBA16 original_pixel_rgba(ImageReview, GoInt x, GoInt y) = 0;
  virtual ByteString original_format_percent(const ByteString &, double) = 0;
};
// Recovered (Ws5yVBd@1c53600): constructor defaults of 0.3 transparency,
// 0.8 darkness, and exactly 19 target filenames. These defaults do not prove
// all possible runtime configurations.
AnalyzerConfig captured_configuration() {
  return {0.3,
          0.8,
          {"stone.png", "cobblestone.png", "dirt.png", "grass_block_side.png",
           "sand.png", "gravel.png", "netherrack.png", "deepslate.png",
           "andesite.png", "diorite.png", "granite.png", "coal_ore.png",
           "iron_ore.png", "gold_ore.png", "diamond_ore.png", "emerald_ore.png",
           "lapis_ore.png", "redstone_ore.png", "copper_ore.png"}};
}
// vY4Ic77gWf1@1c5e640: one of four case-sensitive byte substrings in the member
// path, then exact case-sensitive WindowsBase equality against 19 names.
// No path-start, slash normalization or word/directory boundary required.
bool is_target_texture(TextureContracts &r, const AnalyzerConfig &config,
                       const ByteString &path) {
  bool location = false;
  for (const auto needle :
       {"assets/minecraft/textures/block", "assets/minecraft/textures/blocks",
        "textures/blocks", "textures/block"})
    if (path.find(needle) != ByteString::npos) {
      location = true;
      break;
    }
  if (!location)
    return false;
  const auto name = r.windows_base(path);
  for (const auto &target : config.texture_names)
    if (name == target)
      return true;
  return false;
}
// Recovered (mYwKakbqjmw8@1c5f7e0): sample every fourth row while inspecting
// every x, then every fourth column while inspecting every y. Alpha < 0x8000,
// fraction strictly > 0.7; qualifying rows > height/16 or columns > width/16.
// Both passes occur before final decision. Small synthetic bounds fixtures
// cover ordinary and nonzero origin. Original int
// overflow/negative/dimensions/runtime contracts remain, including original
// double NaN behavior for zero denominators.
bool has_transparent_line_pattern(TextureContracts &r, ImageReview image) {
  const auto b = r.original_image_bounds(image);
  GoInt rows = 0, columns = 0;
  const auto width = b.max_x - b.min_x, height = b.max_y - b.min_y;
  for (GoInt y = b.min_y; y < b.max_y; y += 4) {
    GoInt transparent = 0;
    for (GoInt x = b.min_x; x < b.max_x; ++x)
      if (r.original_pixel_rgba(image, x, y).a < 0x8000)
        ++transparent;
    if (static_cast<double>(transparent) / static_cast<double>(width) > 0.7)
      ++rows;
  }
  for (GoInt x = b.min_x; x < b.max_x; x += 4) {
    GoInt transparent = 0;
    for (GoInt y = b.min_y; y < b.max_y; ++y)
      if (r.original_pixel_rgba(image, x, y).a < 0x8000)
        ++transparent;
    if (static_cast<double>(transparent) / static_cast<double>(height) > 0.7)
      ++columns;
  }
  return rows > height / 16 || columns > width / 16;
}
// jMJD7MsHqZ5I@1c5ebe0: member.Open, io.ReadAll (no observed bound here),
// bytes.Reader, image.Decode. Archive/IO/actual decoder/color provider and
// deferredClose/errors retained by original_zip_member_readall_decode_image.
Result<TextureResult> analyze_texture(TextureContracts &r,
                                      const AnalyzerConfig &config,
                                      const ZipEntryReview &entry) {
  const auto image = r.original_zip_member_readall_decode_image(entry);
  if (image.error.present())
    return {{}, image.error};
  const auto b = r.original_image_bounds(image.value);
  GoInt transparent = 0, very_transparent = 0, dark = 0;
  const GoInt pixel_count =
      (b.max_x - b.min_x) *
      (b.max_y - b.min_y); // original GoInt signed64 overflow contract
  for (GoInt y = b.min_y; y < b.max_y; ++y)
    for (GoInt x = b.min_x; x < b.max_x; ++x) {
      const auto color = r.original_pixel_rgba(image.value, x, y);
      if (color.a < 0x8000) {
        ++transparent;
        if (color.a < 0x4000)
          ++very_transparent;
      }
      // uint32 channel-sum semantics; uses Go color.Color.RGBA
      // premultiplication as supplied by original provider, not independent RGB
      // interpretation.
      if ((static_cast<std::uint32_t>(color.r + color.g + color.b) / 3) <
              0x2000 &&
          color.a > 0x8000)
        ++dark;
    }
  const auto n = static_cast<double>(pixel_count);
  TextureResult result{r.windows_base(entry.name),
                       static_cast<double>(transparent) / n,
                       static_cast<double>(dark) / n,
                       false,
                       {}};
  if (result.transparency > config.transparency_threshold) {
    result.suspicious = true;
    result.reason = r.original_format_percent("High transparency: %.2f%%",
                                              result.transparency * 100);
  } else if (static_cast<double>(very_transparent) / n > 0.15) {
    result.suspicious = true;
    result.reason = r.original_format_percent(
        "Ton of transparent pixels: %.2f%%",
        static_cast<double>(very_transparent) / n * 100);
  } else if (result.darkness > config.dark_threshold) {
    result.suspicious = true;
    result.reason = r.original_format_percent("ton of dark pixels: %.2f%%",
                                              result.darkness * 100);
  }
  if (has_transparent_line_pattern(r, image.value)) {
    result.suspicious = true;
    if (!result.reason.empty())
      result.reason += "; ";
    result.reason += "Pattern detected";
  }
  return {result, {}};
}
// AnalyzeTexturePack@1c5e140: selected-member attempted count increments even
// on read/decode error. Only successful images enter the denominator. Retain
// only suspicious texture records. IsXRay requires a ratio strictly greater
// than 0.2; exactly 20 percent is false.
Result<PackResult> analyze_zip_texture_statistics(TextureContracts &r,
                                                  const AnalyzerConfig &config,
                                                  const ByteString &path) {
  const auto archive = r.original_open_zip_directory(path);
  if (archive.error.present())
    return {{}, archive.error};
  r.original_defer_archive_close();
  PackResult out;
  for (const auto &member : archive.value) {
    if (!is_target_texture(r, config, member.name))
      continue;
    ++out.total_blocks;
    const auto texture = analyze_texture(r, config, member);
    if (texture.error.present())
      continue;
    ++out.analyzed_blocks;
    if (texture.value.suspicious)
      out.suspicious_blocks.push_back(texture.value);
  }
  if (out.analyzed_blocks > 0) {
    out.score = static_cast<double>(out.suspicious_blocks.size()) /
                static_cast<double>(out.analyzed_blocks);
    out.is_xray = out.score > 0.2;
  }
  // name/path/logo/detection_method/blacklisted_files filled by OUTER worker,
  // not this method. Do not invent those fields from this body's file path.
  return {out, {}};
}
// Recovered (ePYfxuw0N@1c5bfc0): first five exact, case-sensitive basename
// tests, then four lowercase path substrings, then four uint32 constants. Any
// one qualifies. The scalar originates at pack-info offset 56, copied from an
// archive member Header field at offset 76. Its exact provenance is the last
// successfully read pack.png-substring member, mapped in
// java_resourcepack_metadata.cpp.
bool is_blacklisted_member(TextureContracts &r, const ByteString &path,
                           std::uint32_t pack_scalar) {
  const auto base = r.windows_base(path);
  for (const auto name :
       {"xray.json", "xray_top.json", "xray_mirrored_all.json",
        "xray_mirrored.json", "xray_all.json"})
    if (base == name)
      return true;
  const auto lower = r.to_lower(path);
  for (const auto needle : {"/xray/", "\\xray\\", "x-ray", "xray"})
    if (lower.find(needle) != ByteString::npos)
      return true;
  for (const auto value : {0x3cec4bcau, 0x3b41c3f3u, 0x52d48d10u, 0xf53d9611u})
    if (pack_scalar == value)
      return true;
  return false;
}
// Outer NlLamvI686Y/resourcepack workers, icon extraction, directory packs,
// shared-name/scalar propagation, concurrent merge, nmJf9uh/debug output and
// JEg1SQOq final gzip/JSON envelope is mapped in java_resourcepack_report.cpp.
// This is the verified texture core; parent enumeration and merge are mapped in
// java_resourcepack_parent.cpp.
struct PackInfoReview {
  ByteString name, logo;
  std::vector<ByteString> member_names;
  std::uint32_t scalar;
};
struct MergedPackResults {
  std::vector<PackResult> detected, suspected;
  std::vector<ByteString> other_names;
};
struct PackMergeContracts : TextureContracts {
  virtual ByteString windows_join(const std::vector<ByteString> &) = 0;
  virtual void original_locked_merge(const std::function<void()> &) = 0;
  virtual void original_deferred_waitgroup_and_semaphore_completion() = 0;
};
// NlLamvI686Y.func7@1c59580. Inputs already contain pack name, logo, all
// member names and shared scalar from rSw metadata. This core is independent
// of native ZIP/provider metadata accuracy and original concurrent ordering.
void merge_one_pack(PackMergeContracts &r, const AnalyzerConfig &config,
                    const ByteString &root, const PackInfoReview &info,
                    MergedPackResults &out) {
  PackResult row;
  row.name = info.name;
  row.path = r.windows_join({root, info.name});
  row.logo = info.logo;
  for (const auto &member : info.member_names)
    if (is_blacklisted_member(r, member, info.scalar))
      row.blacklisted_files.push_back(member);
  bool texture_xray = false;
  const auto lower = r.to_lower(info.name);
  // Pixel/texture analysis happens only for .zip names in THIS worker.
  // Directory packs can match blacklist; no texture decoding here for folders.
  if (lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".zip") == 0) {
    const auto analyzed = analyze_zip_texture_statistics(r, config, row.path);
    if (!analyzed.error.present()) {
      texture_xray = analyzed.value.is_xray;
      row.suspicious_blocks = analyzed.value.suspicious_blocks;
      row.score = analyzed.value.score;
      row.analyzed_blocks = analyzed.value.analyzed_blocks;
      row.total_blocks = analyzed.value.total_blocks;
    }
    // Analysis error gets no error status in this result: zero score may place
    // pack name in other_names. "other_names" must not be interpreted as safe.
  }
  if (!row.blacklisted_files.empty()) {
    row.is_xray = true;
    row.detection_method = texture_xray ? "both" : "pattern";
  } else if (texture_xray) {
    row.is_xray = true;
    row.detection_method = "texture";
  }
  r.original_locked_merge([&] {
    if (row.is_xray)
      out.detected.push_back(row);
    else if (row.score > 0.1 || !row.blacklisted_files.empty())
      out.suspected.push_back(row);
    else
      out.other_names.push_back(info.name);
  });
  r.original_deferred_waitgroup_and_semaphore_completion();
}

} // namespace ocean::reconstructed::minecraft_texture_review
