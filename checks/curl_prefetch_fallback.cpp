#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: C:\Windows\Prefetch directory entries and a caller-supplied baseline time.
//   Gate: Requires curl.exe- prefix, .pf extension, file ModTime strictly after baseline, a
//         parseable curl.exe record, and a nonignored referenced path.
//   Output: Returns referenced paths in encounter order; duplicates remain.
//   Failure: Zero baseline, directory/stat/parse errors, and rejected records are skipped without a
//            report.

namespace ocean::reconstructed::shared_curl_prefetch_fallback {
struct Time {
    std::uint64_t wall,ext,location;
};
struct Entry {
    bool directory;
    ByteString name;
};
struct Directory {
    std::vector<Entry> entries;
    bool error;
};
struct Stat {Time modified;bool error;};
struct Prefetch {
    ByteString executable;
    std::vector<ByteString> referenced_files;
    bool error;
};
struct Contracts {
    virtual Directory original_read_directory(const ByteString&)=0;
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
    virtual bool original_unicode_equal_fold(const ByteString&,const ByteString&)=0;
    virtual ByteString original_windows_filepath_join(const std::vector<ByteString>&)=0;
    virtual Stat original_stat(const ByteString&)=0;
    virtual bool original_after(Time,Time)=0;
    virtual Prefetch original_parse_prefetch_file(const ByteString&)=0; //DCZm@c80? exactmetadatareport
    virtual bool reviewed_curl_executable(const ByteString&)=0;
    virtual bool reviewed_ignored_dependency(const ByteString&)=0;
};
std::vector<ByteString> collect(Contracts& runtime,Time baseline) { //clx@125ef00
    std::vector<ByteString> result;
    if(baseline.wall==0 && baseline.ext==0) return result; //location ignored
    const ByteString root="C:\\Windows\\Prefetch";
    const auto directory=runtime.original_read_directory(root);
    if(directory.error) return result;
    for(const auto& entry:directory.entries) {
        if(entry.directory) continue;
        const auto lower=runtime.original_unicode_lowercase(entry.name);
        if(lower.size()<9 || lower.compare(0,9,"curl.exe-")!=0) continue;
        ByteString extension;
        for(std::size_t at=entry.name.size();at>0;) {
            const auto c=entry.name[--at];
            if(c=='/' || c=='\\') break;
            if(c=='.') {extension=entry.name.substr(at);break;}
        }
        if(!runtime.original_unicode_equal_fold(extension,".pf")) continue;
        const auto path=runtime.original_windows_filepath_join({root,entry.name});
        const auto metadata=runtime.original_stat(path);
        if(metadata.error || !runtime.original_after(metadata.modified,baseline)) continue;
        const auto parsed=runtime.original_parse_prefetch_file(path);
        if(parsed.error || !runtime.reviewed_curl_executable(parsed.executable)) continue;
        for(const auto& file:parsed.referenced_files)
            if(!runtime.reviewed_ignored_dependency(file)) result.push_back(file);
    }
    return result; //duplicates preserved untilroot150dedup
}
//9 original entry-gate cases+7 original parser-output cases returned. Prefix exactly
//9 bytes curl.exe-, extensionEqualFold.pf. Filename hash itself not validated. Stat
// modifiedstrictAfterbaseline; no latestRun/count test here. Synthetic DirEntry/stat/
// The concrete recovered provider is parse_prefetch_file in windows_prefetch_parser.cpp.
// API/file/native/source neverexecuted. VM-only readable C++ never compiled/run.
}
