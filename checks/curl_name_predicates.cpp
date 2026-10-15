#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Collected executable rows and their referenced-file strings.
//   Gate: Selects rows whose Windows basename EqualFold-matches curl.exe, then rejects blank, $mft,
//         curl.exe, .dll, .lnk, and .nls dependencies.
//   Output: Returns the remaining paths in source order with duplicates intact.
//   Failure: The raw row producer is outside this file; trimming is only a blankness test and is
//            not assigned back to the path.

namespace ocean::reconstructed::shared_curl_name_predicates {
struct Contracts {
    virtual ByteString original_unicode_trim_space(const ByteString&)=0;
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
    virtual bool original_unicode_equal_fold(const ByteString&,const ByteString&)=0;
    virtual ByteString original_windows_filepath_base(const ByteString&)=0;
};
bool curl_executable(Contracts& runtime,const ByteString& path) { //c5m@1260300
    return runtime.original_unicode_equal_fold(runtime.original_windows_filepath_base(path),"curl.exe");
}
bool ignored_dependency(Contracts& runtime,const ByteString& original) { //a4Y@1260740
    if(runtime.original_unicode_trim_space(original).empty()) return true;
    // Original tests lowercase ORIGINAL bytes, doesn't assign trimmed return toinput.
    if(runtime.original_unicode_lowercase(original).find("$mft")!=ByteString::npos) return true;
    ByteString windows_path=original;
    for(auto& c:windows_path) if(c=='/') c='\\';
    const auto basename=runtime.original_windows_filepath_base(windows_path);
    if(runtime.original_unicode_equal_fold(basename,"curl.exe")) return true;
    ByteString extension;
    for(std::size_t at=basename.size();at>0;) {
        const auto c=basename[--at];
        if(c=='/' || c=='\\') break;
        if(c=='.') {extension=basename.substr(at);break;}
    }
    extension=runtime.original_unicode_lowercase(extension);
    return extension==".dll" || extension==".lnk" || extension==".nls";
}
struct CollectedRow {
    ByteString executable;
    std::vector<ByteString> referenced_files;
};
std::vector<ByteString> from_collected_rows(Contracts& runtime,const std::vector<CollectedRow>& rows) {
    std::vector<ByteString> result;
    for(const auto& row:rows) if(curl_executable(runtime,row.executable))
        for(const auto& path:row.referenced_files)
            if(!ignored_dependency(runtime,path)) result.push_back(path);
    return result; //b7Z@125ebe0 stride144, executable16, files112; no helperdedup
}
//30 original predicate paths returned with explicit ASCIIUnicode/basename models.
// c5m exactbasenameEqualFold, no containscurl/noextensionlesscurl. a4Y returnsIGNORE
// for empty/whitespace,$mftanywhere, exactcurlbasename or3extensions. Originalroot
// BtZw125e360 callsb7Zglobal572e100/108/110; ONLYiflistempty fallbackclx with Time global572e0c0/c8/d0 (not a slice).
// First-stage144stride/exec16/files112 proved4originalrowfixtures, two-rowpositive
// andduplicatespreserved. Root later exactdedup, report. Raw collected-row
// producer/fallbackfiletime/root
// Root fallback, exact dedup and reporting are in curl_root_flow.cpp and curl_prefetch_fallback.cpp.
// VM-only readable source never compiled/run.
}
