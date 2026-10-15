#include "../session/session_types.hpp"
#include <functional>
#include <algorithm>
// Recovered behavior summary:
//   Input: HKLM TaskCache task Author, Actions bytes, and Path values.
//   Gate: Author must match ^DESKTOP-.*$ and Actions must contain five bytes 63 00 6D 00 64 at any
//         byte alignment.
//   Output: Emits a TaskSched console/debug row with author and Path after removing every
//           backslash.
//   Failure: Root/name/value failures skip work; callback errors recover silently and no task time
//            or execution state is checked.

namespace ocean::reconstructed::shared_task_actions {
using Handle=std::uint64_t;
template<class T>struct Read {
    T value{};
    bool error=false;
};
struct Contracts{
 virtual Read<Handle> open_key(Handle,const ByteString&,std::uint32_t)=0;
 virtual Read<std::vector<ByteString>> subkeys(Handle,std::int64_t)=0;
 virtual Read<ByteString> string_value(Handle,const ByteString&)=0;
 virtual Read<Bytes> binary_value(Handle,const ByteString&)=0;
 virtual Handle must_compile_go_regexp(const ByteString&)=0;
 virtual bool regexp_match(Handle,const ByteString&)=0;
 virtual void close_ignoring_error(Handle)=0;
 virtual void recover_silently(const std::function<void()>&)=0;
 virtual void print_text(const ByteString&)=0;
 virtual void append_debug_author_path(const ByteString&,const ByteString&)=0;
};
bool action_window_match(Contracts& rt,const Bytes& actions,const Bytes& pattern){ //oI4vkhA0roKw@12c2380
 bool found=false;rt.recover_silently([&]{
  for(std::int64_t i=0;i<static_cast<std::int64_t>(actions.size())-4;++i)
   if(pattern.size()==5 && std::equal(pattern.begin(),pattern.end(),actions.begin()+i)){found=true;break;}
 });return found;
}
void check(Contracts& rt){ //VU3hi3tAy@12c4760
 auto root=rt.open_key(0x80000002,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\",0x20019);
 if(root.error)return;
 struct Close {
  Contracts& rt;
  std::vector<Handle> handles;
  ~Close() {
   for(auto i=handles.rbegin();i!=handles.rend();++i)
    rt.close_ignoring_error(*i);
  }
 } close{rt,{root.value}};
 auto names=rt.subkeys(root.value,-1);if(names.error)return;
 const auto author_pattern=rt.must_compile_go_regexp("^DESKTOP-.*$");
 for(const auto& name:names.value){
  auto key=rt.open_key(root.value,name,0x20019);if(key.error)continue;close.handles.push_back(key.value);
  auto author=rt.string_value(key.value,"Author");if(author.error || !rt.regexp_match(author_pattern,author.value))continue;
  auto actions=rt.binary_value(key.value,"Actions");if(actions.error)continue;
  auto path=rt.string_value(key.value,"Path");if(path.error)continue;
  ByteString flattened=path.value;flattened.erase(std::remove(flattened.begin(),flattened.end(),'\\'),flattened.end());
  if(!action_window_match(rt,actions.value,Bytes{99,0,109,0,100}))continue;
  rt.print_text("Task Schedule:::Out of instance:::The user created their own scheduled task");
  rt.append_debug_author_path(author.value,flattened);
 }
 //Debug ["Detect","TaskSched",author,Path-with-ALL-backslashes-removed].
 //Five-byte substring only, at ANY alignment. Not an action-structure parse;
 //neither full UTF16 cmd.exe nor a terminator is required. No time/boot gate,
 //execution proof, warning-global write or deduplication. Child defers run at
 //function return, in reverse open order, before root close.
}
//Eighteen original routes including actual author-regexp comparisons; synthetic
//registry providers and standard regexp contract. Never compiled or executed.
}
