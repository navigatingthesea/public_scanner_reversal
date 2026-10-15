#include "../session/session_types.hpp"
#include <functional>
#include <unordered_map>
// Recovered behavior summary:
//   Input: Every file under C:\windows\prefetch and its complete binary contents.
//   Gate: Skips names matching the exact case-sensitive eight-hyphen .pf regex; otherwise detects
//         repeated entire-file contents.
//   Output: Appends a bypass warning for each duplicate and a folder-missing debug row if traversal
//           aborts.
//   Failure: Any walk/read error stops traversal; content keys may include NUL and there is no
//            hash, size, magic, or time gate.

namespace ocean::reconstructed::shared_type_bypass {
struct Error {
    ByteString text;
}; //nil/non-nil Go error identity retained by provider
struct FileInfo {
    bool is_directory;
    ByteString name;
};
struct ReadResult {
    ByteString bytes;
    const Error* error;
};
struct Contracts {
 virtual const Error* walk_windows_path(const ByteString&,
  const std::function<const Error*(const ByteString&,const FileInfo*,const Error*)>&)=0;
 //Go filepath.Walk contract: lexical traversal, errors passed to callback; callback
 //error stops walk. Native traversal/ReadFile are providers, not executed here.
 virtual ReadResult read_entire_file(const ByteString&)=0; //os.ReadFile, binary-safe
 virtual std::uint64_t regexp_must_compile(const ByteString& pattern)=0;
 virtual bool regexp_match(std::uint64_t compiled,const ByteString& name)=0;
 virtual ByteString go_windows_filepath_base(const ByteString&)=0;
 virtual void append_warning(const ByteString&)=0; //572e7a0 slice
 virtual void append_debug(const std::vector<ByteString>&)=0; //572e8e0
 virtual void console_report(const ByteString&)=0;
 virtual void recover_go_panic(const std::function<void()>&,
                             const std::vector<ByteString>& recovery_record)=0;
};
void check(Contracts& rt) { //HwHNxT@12c6060; callback.func4@12c6d00
 rt.recover_go_panic([&]{
  //Fresh map for this invocation. Key is ENTIRE binary file contents, with NULs.
  //It is neither a filename map nor a checksum map. First path remains stored.
  std::unordered_map<ByteString,ByteString> first_path_for_contents;
  const ByteString expression=R"(^(.*?)-{8}\.pf$)";
  const auto compiled=rt.regexp_must_compile(expression);
  //MustCompile occurs before walk. This exact valid expression is case-sensitive.
  const Error* error=rt.walk_windows_path(R"(C:\windows\prefetch)",
   [&](const ByteString& path,const FileInfo* info,const Error* input_error)->const Error* {
    if(input_error)return input_error; //before FileInfo access
    if(info->is_directory)return nullptr;
    const auto file=rt.read_entire_file(path);
    if(file.error)return file.error; //not ignored: aborts whole walk
    //Read precedes filename regex, even for entries later excluded.
    if(rt.regexp_match(compiled,info->name))return nullptr;
    auto previous=first_path_for_contents.find(file.bytes);
    if(previous==first_path_for_contents.end()){
     first_path_for_contents.emplace(file.bytes,path);
    } else {
     const auto current_name=rt.go_windows_filepath_base(path);
     const auto first_name=rt.go_windows_filepath_base(previous->second);
     rt.append_warning("Bypass method detected in: "+first_name+" > "+current_name);
     //No update, distinct-path test, warning deduplication or Debug append.
    }
    return nullptr;
   });
  if(error){
   //All walk/read failures use this wording, not only a missing root folder.
   rt.console_report("Bypass Method (Prefetch Folder deleted):::Boot instance:::Prefetch Folder not found.");
   rt.append_debug({"Detect","PF_FolderMissing",error->text});
  }
 },{"Crash","TypeBypass","File operation failed"}); //func1@12efdc0
}
//20 interpreted original routes: root success/error, callback input/read errors,
//directories, new/duplicate/empty/NUL contents, identical paths, recovery logger,
//and7 exact ASCII regex fixtures. Forced regex controls separately labeled.
//The regex means eight '-' characters followed by lowercase.pf, not8hex digits.
//There is no required.pf extension, file magic/time/boot gate, hash or size limit
//in this callback; read_entire_file failure and Go allocation panic remain visible.
//Application logic reconstructed; standard OS/regex/panic contracts explicit.
//Guest-only readable source; never compiled or run.
}
