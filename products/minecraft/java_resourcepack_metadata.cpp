#include "../../session/session_types.hpp"
#include <cmath>
#include <optional>
namespace ocean::reconstructed::resourcepack_metadata_review {
// Purpose: collect a resource pack's name, member paths, display image, shared
// CRC scalar, and optional CIT durability metadata from a ZIP or directory.
struct ErrorWords {
  std::uint64_t type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct FileInfoContracts {
  virtual ByteString original_name() = 0;
  virtual bool original_is_directory() = 0;
  virtual GoInt original_size() = 0;
};
struct ZipMember {
  ByteString original_name;
  std::uint64_t uncompressed_size64 = 0; // captured Header field96
  std::uint32_t header_crc32 =
      0; // captured Header field76, official-layout inference
  std::uint32_t original_file_mode =
      0; // Mode provider, not external attributes directly
};
struct ByteRead {
  ByteString bytes;
  ErrorWords error;
};
struct MemberRead {
  bool opened = false;
  ByteRead read;
};
struct CITRecord {
  ByteString pack_name;
  std::vector<ByteString> items, property_paths;
};
struct CITState {
  std::uint64_t opaque_original_accumulator = 0;
};
struct Metadata { // logical model of original72B type375d200
  ByteString pack_name, logo;
  std::vector<ByteString> member_names;
  std::uint32_t shared_icon_crc32 = 0;
  std::optional<CITRecord> cit;
};
struct DirectoryState {
  ByteString full_pack_path, logo;
  std::vector<ByteString> relative_names;
  CITState cit;
};
struct ZipOpen {
  bool has_error = false;
  std::vector<ZipMember> members;
};
struct RelativePath {
  ByteString path;
  ErrorWords error;
};
struct MetadataContracts {
  virtual ByteString original_windows_join(const ByteString &root,
                                           const ByteString &name) = 0;
  virtual ByteString original_lower_utf8(const ByteString &) = 0;
  virtual ZipOpen original_zip_open(const ByteString &) = 0;
  // Open and ReadAll are separate failure gates. Reader Close is attempted
  // immediately after ReadAll, including a ReadAll error. No input-byte bound
  // is observed here. Real ZIP/decompressor/CRC-check/close paths are
  // contracts.
  virtual MemberRead
  original_zip_member_open_read_all_close(const ZipMember &) = 0;
  virtual void original_zip_close_ignoring_result() = 0;
  virtual ByteString original_base64_encode(const ByteString &) = 0;
  virtual ByteRead original_read_whole_file(const ByteString &) = 0;
  virtual RelativePath original_windows_relative(const ByteString &root,
                                                 const ByteString &full) = 0;
  virtual std::optional<CITRecord>
  original_zip_cit_collector(const std::vector<ZipMember> &,
                             const ByteString &name) = 0;
  virtual CITState original_new_directory_cit_state(const ByteString &name) = 0;
  virtual void original_cit_per_directory_file(CITState &,
                                               const ByteString &relative,
                                               const ByteString &full,
                                               GoInt size) = 0;
  virtual std::optional<CITRecord>
  original_finalize_directory_cit(const CITState &) = 0;
  // Walk invokes directory_callback below for entries. Actual enumeration,
  // root callback, ordering, errors and panic behavior remain provider
  // contracts.
  virtual ErrorWords original_walk_directory(const ByteString &,
                                             DirectoryState &) = 0;
};
// Recovered rSw@1c5a260 / func3 expression, applied to Base64 length before
// prefix addition. Larger values become literal "unk". It is not a bound on
// bytes read: content has already been read and encoded before this decision.
ByteString logo_from_raw(MetadataContracts &r, const ByteString &raw) {
  const auto encoded = r.original_base64_encode(raw);
  const auto estimate = (std::ceil(static_cast<double>(encoded.size()) / 3.0) *
                         4.0 * 0.5624896334383812) /
                        1000.0;
  if (estimate > 1024.0)
    return "unk";
  return "data:image/jpeg;base64," + encoded;
}
// No image decoding/PNG validity check appears in this caller: raw bytes are
// encoded with a fixed JPEG data prefix, even though selector text is pack.png.
// Exact boundaries under the canonical Base64 provider: 1,024,017 raw bytes
// kept;
// 1,024,018 raw bytes produce "unk". Other encoder/provider paths are separate.

// Recovered (rSwmhRCxh.func3@1c5b8e0): callback error is returned before
// collecting. The filepath.Rel error is ignored; its returned string is still
// appended. Directories (including a root callback ".") are appended as well as
// files.
ErrorWords directory_callback(MetadataContracts &r, DirectoryState &state,
                              const ByteString &full_path,
                              FileInfoContracts &info,
                              ErrorWords callback_error) {
  if (callback_error.present())
    return callback_error;
  const auto relative =
      r.original_windows_relative(state.full_pack_path, full_path);
  state.relative_names.push_back(
      relative.path); // includes empty string on a Rel error
  if (!info.original_is_directory())
    r.original_cit_per_directory_file(state.cit, relative.path, full_path,
                                      info.original_size());
  if (relative.path.find("pack.png") != ByteString::npos) {
    // No IsDir/size guard for THIS logo read. CIT uses separate reviewed
    // limits.
    const auto read = r.original_read_whole_file(full_path);
    if (!read.error.present())
      state.logo = logo_from_raw(r, read.bytes);
  }
  return {};
}

// Recovered (rSwmhRCxh@1c5a260): FileInfo.Name() is called at the original
// phases. Parent enumeration/orchestration now reviewed in
// java_resourcepack_parent.cpp with symbolic providers; real
// concurrency/panic/native IO are contracts. This helper can also produce empty
// metadata for a non-directory non-ZIP file; that does not prove the parent
// selects that file.
std::optional<Metadata> inspect_metadata(MetadataContracts &r,
                                         const ByteString &root,
                                         FileInfoContracts &info) {
  const auto full_path = r.original_windows_join(root, info.original_name());
  Metadata out;
  bool zip_opened = false;
  bool is_zip = false;
  if (!info.original_is_directory()) {
    const auto lower_name = r.original_lower_utf8(info.original_name());
    is_zip = lower_name.size() >= 4 &&
             lower_name.compare(lower_name.size() - 4, 4, ".zip") == 0;
  }
  if (is_zip) {
    const auto zip = r.original_zip_open(full_path);
    if (zip.has_error)
      return std::nullopt;
    zip_opened = true;
    for (const auto &member : zip.members) {
      if (member.uncompressed_size64 == 0 ||
          (member.original_file_mode & 0x80000000U))
        continue;
      out.member_names.push_back(member.original_name);
      // Case-sensitive byte substring; nested/prefix/suffix variants match.
      if (member.original_name.find("pack.png") == ByteString::npos)
        continue;
      const auto read = r.original_zip_member_open_read_all_close(member);
      if (!read.opened || read.read.error.present())
        continue;
      out.logo = logo_from_raw(
          r, read.read.bytes); // empty bytes still replace prior logo
      out.shared_icon_crc32 =
          member.header_crc32; // set even when logo becomes "unk"
    }
    out.cit = r.original_zip_cit_collector(zip.members, info.original_name());
  } else if (info.original_is_directory()) {
    DirectoryState state;
    state.full_pack_path = full_path;
    state.cit = r.original_new_directory_cit_state(info.original_name());
    const auto error = r.original_walk_directory(full_path, state);
    if (error.present())
      return std::nullopt;
    out.cit = r.original_finalize_directory_cit(state.cit);
    out.logo = state.logo;
    out.member_names = state.relative_names;
    out.shared_icon_crc32 = 0;
  }
  out.pack_name = info.original_name();
  if (zip_opened)
    r.original_zip_close_ignoring_result();
  return out;
}
// Normal return order is shown; original Go defer/panic cleanup remains a
// contract. Filename list has no dedup here. ZIP last successful pack.png
// substring match overwrites logo +CRC; later failures preserve prior values.
// Directory metadata leaves CRC zero. Downstream Nl.func7 reuses this one
// shared icon scalar for every filename fed to ePY blacklist predicates.
// The detected 144-byte pack report includes Logo, BlacklistedFiles, and
// texture stats
// in the previously traced JSON/gzip X-RAY payload; metadata creation alone
// is not a claim that every pack/name/content gets uploaded.
} // namespace ocean::reconstructed::resourcepack_metadata_review
