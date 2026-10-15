#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Certificate filenames under C:\Program Files (x86)\Microsoft SDKs\Windows\v*\Bin\*.cer.
//   Gate: The first version directory with any glob match qualifies; certificate contents and
//         signatures are not read.
//   Output: Emits one FakeSig report and structured path row.
//   Failure: Root glob failure aborts; inner glob failures skip that version; recovery emits fixed
//            crash rows.

namespace ocean::reconstructed::shared_fake_signatures_heuristic {
struct Glob {
    std::vector<ByteString> paths;
    bool error;
};
struct Contracts {
    virtual ByteString original_windows_filepath_join(const std::vector<ByteString>&)=0;
    virtual Glob original_windows_filepath_glob(const ByteString&)=0;
    virtual void append_original_report(const ByteString&)=0;
    virtual void append_structured_detection(const std::vector<ByteString>&)=0;
    virtual void register_recovery(const ByteString&,const ByteString&)=0;
};
struct Found {
    bool present=false;
    ByteString path;
};
Found find_certificate(Contracts& runtime,const ByteString& root) { //func3@1297c80
    runtime.register_recovery("FakeSignatures_DirCheck","Failed checking directory for certificates");
    const auto versions=runtime.original_windows_filepath_glob(
        runtime.original_windows_filepath_join({root,"v*"}));
    if(versions.error) return {};
    for(const auto& version:versions.paths) {
        const auto certificates=runtime.original_windows_filepath_glob(
            runtime.original_windows_filepath_join({version,"Bin","*.cer"}));
        if(!certificates.error && !certificates.paths.empty()) return {true,certificates.paths.front()};
    }
    return {};
}
void run(Contracts& runtime) { //MhijPx@1297a40
    runtime.register_recovery("FakeSignatures","Main signature check failed");
    const ByteString root="C:\\Program Files (x86)\\Microsoft SDKs\\Windows";
    const auto certificate=find_certificate(runtime,root);
    if(!certificate.present) return;
    runtime.append_original_report("Fake Signature:::Out of instance:::User faked a digital signature/s to bypass a screenshare");
    runtime.append_structured_detection({"Detect","FakeSig",certificate.path,root});
}
// Original found bool is independent of returned path bytes, preserving even an
// empty provider path in a nonempty Glob slice without an invented content check.
//6 original predicate fixtures returned plus4 recovery cases. Root Glob error aborts;
// inner Glob error skips version; first nonempty match wins, no other versions scanned.
// It ONLY tests filename-pattern presence, with no certificate reads, validation,
// digital signature/WinVerifyTrust/key-store checks or attribution/timestamp checks.
// Original report's intent assertion is a heuristic label. Native filepath Join/Glob
// semantics remain contracts; probes used synthetic outputs and recorded components.
// Recovery rows [Crash,label,message] fixed, recovered values discarded. VM-only
// readable C++ never compiled/run.
}
