#include "../../session/session_types.hpp"
#include <memory>
namespace ocean::reconstructed::minecraft_working_set_check_review {
// Purpose: count committed working-set pages whose recovered share-count field
// is exactly seven. The application reports "Cheat Injection J" only when the
// count is greater than 40,000; this remains a heuristic label.
using Word = std::uint64_t;
struct Error {
  Word type = 0, data = 0;
  bool present() const { return type != 0; }
};
struct OpenResult {
  Word handle = 0;
  Error error;
};
struct Receiver {
  std::uint32_t pid = 0;
  Word handle = 0;
}; // 368c800:PID0,handle8,slice16
struct Region {
  Word base = 0, size = 0;
  std::uint32_t state = 0;
};
struct PageInfo {
  Word address = 0, flags = 0;
}; // 36723c0,16 original bytes
struct RetainedPage {
  Word address = 0, share_count = 0, flags = 0;
}; // 368c5c0,24 original bytes
struct Contracts {
  virtual OpenResult original_open_process(std::uint32_t access, bool inherit,
                                           std::uint32_t) = 0;
  virtual Error original_close_handle(Word) = 0;
  virtual Error original_virtual_query(Word handle, Word address, Region &,
                                       Word structure_size) = 0;
  virtual Word original_query_working_set_ex(Word handle, PageInfo &,
                                             Word structure_size) = 0;
  virtual void original_diagnostic_log(const ByteString &) = 0;
  virtual void append_debug(const ByteString &level, const ByteString &label,
                            GoInt count) = 0;
  virtual void
      original_register_deferred_receiver_close(std::shared_ptr<Receiver>) = 0;
};
// LINogJc_@1c47f40. Error returns nil; successful zero handle still produces
// a nonnil receiver. The original third field is a nonnil empty slice.
std::shared_ptr<Receiver> open_receiver(Contracts &r, std::uint32_t pid) {
  const auto opened = r.original_open_process(0x418, false, pid);
  if (opened.error.present())
    return {};
  auto receiver = std::make_shared<Receiver>();
  receiver->pid = pid;
  receiver->handle = opened.handle;
  return receiver;
}
// A2.deferwrap1@1c47f00 ignores close error and does not zero this handle.
void close_receiver(Contracts &r, const Receiver &receiver) {
  if (receiver.handle)
    r.original_close_handle(receiver.handle);
}
// pwamtcLeBNnS@1c48000. Reads memory-region metadata and page working-set
// attributes. No protection/type filter here; only state 1000 is required.
// Query failures end the region walk. No explicit address ceiling, alignment
// rounding or progress check occurs in this body.
void check_working_set(Contracts &r, const Receiver &receiver) {
  Word address = 0;
  std::vector<RetainedPage> retained;
  for (;;) {
    Region region;
    if (r.original_virtual_query(receiver.handle, address, region, 48)
            .present())
      break;
    if (region.state == 0x1000) {
      for (Word offset = 0; offset < region.size; offset += 0x1000) {
        PageInfo page{region.base + offset, 0};
        const auto success =
            r.original_query_working_set_ex(receiver.handle, page, 16);
        const auto share = (page.flags >> 1) & 7;
        if (success != 0 && (page.flags & 1) != 0 &&
            (share != 0 || (page.flags & 0x600) != 0))
          retained.push_back({page.address, share, page.flags});
      }
    }
    address = region.base + region.size;
  }
  GoInt count = 0;
  for (const auto &page : retained)
    if (page.share_count == 7)
      ++count;
  if (count > 40000) {
    r.original_diagnostic_log("Cheat Injection J:::In instance");
    r.append_debug("Detect", "Cheat Injection J", count);
  }
}
// A2xWbpH@1c47e20 traverses every entry of selected PID slice 57321c0.
// Duplicate PIDs are preserved, nil constructors skipped. Receiver handles
// are deferred until this parent returns, rather than closed per iteration.
void check_selected_pids(Contracts &r, const std::vector<std::uint64_t> &pids) {
  for (const auto pid : pids) {
    auto receiver = open_receiver(r, static_cast<std::uint32_t>(pid));
    if (!receiver)
      continue;
    r.original_register_deferred_receiver_close(receiver);
    check_working_set(r, *receiver);
  }
}
// QueryWorkingSetEx binding is captured psapi.dll global 5729030. Native API
// return and output flags are separate; nonzero return alone is insufficient.
// 7 complete small-page paths validate producer flags/stride. 8 isolated tail
// fixtures validate counting and >40000 threshold; they are not claimed as
// full 40001-page producer runs. 9 constructor/parent/defer paths returned.
// No direct WARNINGS append in this body; logger side effects remain a
// contract. Review text only; no native API, sample or reconstructed C++ ran.
} // namespace ocean::reconstructed::minecraft_working_set_check_review
