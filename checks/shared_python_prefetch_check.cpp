#include "../session/session_types.hpp"
#include <functional>
// Recovered behavior summary:
//   Input: The referenced-files slice of every cached 144-byte Prefetch row.
//   Gate: For each reference containing case-sensitive .PYD, reselects the first case-sensitive
//         .EXE in that row and applies the recovered path rewrite.
//   Output: Appends executable:::Python Executable strings to the shared candidate slice; it emits
//           no warning or debug row here.
//   Failure: Rows without both markers are skipped; no recency gate, file I/O, deduplication, or
//            parent executable-name test occurs.

namespace ocean::reconstructed::shared_python_prefetch {

struct Prefetch144 {
    std::vector<ByteString> referenced_files;
}; // Slice words at offsets 112/120/128 of the original 144-byte record.

struct Contracts {
    virtual void panic_bounds() = 0;
    virtual void recover_callback(const std::function<void()>&) = 0;
    virtual void append_shared_candidate_string(const ByteString&) = 0;
};

void check(Contracts& runtime,
           const std::vector<Prefetch144>& cached_prefetch) {
    // PaNxJEswSLgI @ 0x12acc80
    runtime.recover_callback([&] {
        std::vector<ByteString> pending;
        for (const auto& record : cached_prefetch) {
            for (const auto& reference : record.referenced_files) {
                if (reference.find(".PYD") == ByteString::npos) {
                    continue;
                }

                // Restart from the beginning for every .PYD marker. The .EXE
                // may precede the marker; the first uppercase suffix wins.
                const ByteString* executable = nullptr;
                for (const auto& file : record.referenced_files) {
                    if (file.size() >= 4 && file.ends_with(".EXE")) {
                        executable = &file;
                        break;
                    }
                }
                if (executable == nullptr) {
                    continue;
                }

                auto path = *executable;
                const bool rewrites_path =
                    path.find("\\USERS\\") != ByteString::npos ||
                    path.find("PROGRAM DATA") != ByteString::npos ||
                    path.find("\\WINDOWS\\") != ByteString::npos ||
                    path.find("PROGRAM FILES") != ByteString::npos;
                if (rewrites_path) {
                    const auto users = path.find("\\USERS\\");
                    // Original Index=-1 plus 7 becomes 6 when another path
                    // predicate matched without a USERS component.
                    const std::size_t start =
                        users == ByteString::npos ? 6 : users + 7;
                    if (start > path.size()) {
                        runtime.panic_bounds();
                    }
                    path = "C:\\" + path.substr(start);
                }
                pending.push_back(path + ":::Python Executable");
            }
        }

        // Append the local result slice to the existing global candidate slice
        // at RVAs 0x572e7c0/0x572e7c8/0x572e7d0.
        for (const auto& result : pending) {
            runtime.append_shared_candidate_string(result);
        }
    });

    // There is no clear, deduplication, recency cutoff, Python process lookup,
    // file I/O, or parent-prefetch-name test. All comparisons are case-sensitive.
    // "PROGRAM DATA" includes a space. Paths matching a rewrite predicate but
    // lacking USERS use substr(6), preserving the recovered quirk.
}

// Twenty-two original routes cover forced Index controls and actual marker,
// suffix, ordering, rewrite, and case fixtures. The final aggregation consumes
// this candidate slice without another per-item predicate.

}  // namespace ocean::reconstructed::shared_python_prefetch
