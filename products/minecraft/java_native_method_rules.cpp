#include "../../session/session_types.hpp"
#include <vector>
namespace ocean::reconstructed::minecraft_native_method_rules {
// Recovered: convert native-method evidence into two independently firing SDK
// rules: score 85 for an obfuscated cluster's private executable target and
// score 80 for a missing backing artifact under the recovered artifact gates.
struct Method {
    ByteString name;                // original method+0
    bool flag136, flag216, flag256; // native access bit, pointer read success, unchanged slot
    std::uint64_t native_address;   // +208
    ByteString backing_name240;     // +240, distinct from +224
    bool flag257, flag258,
        flag259; // query success, private committed executable, backing path missing
};
struct Cluster {
    ByteString artifact;
    bool obfuscation_confidence;               // context+64, reviewed dUB
    bool temporary_artifact, missing_artifact; // +65/+66
};
struct Contracts {
    virtual void append_original_rule_match(const ByteString &, std::int64_t) = 0;
    virtual void append_private_native_evidence(const ByteString &, std::uint64_t) = 0;
    virtual void append_native_backing_evidence(const ByteString &, const ByteString &) = 0;
};
void evaluate(Contracts &output, const Cluster &cluster, const std::vector<Method> &methods) {
    // Original class methods slice at+128, stride296. This is per current class.
    for (const auto &method : methods) {
        if (!method.flag136 || !method.flag216 || !method.flag256 || method.native_address == 0)
            continue;
        if (cluster.obfuscation_confidence && method.flag257 && method.flag258 &&
            method.backing_name240.empty()) {
            output.append_original_rule_match("CLUSTER_PRIVATE_NATIVE", 85); // 1e83fb5
            output.append_private_native_evidence(method.name, method.native_address);
        }
        if (cluster.obfuscation_confidence && method.flag259 &&
            (cluster.artifact.empty() || cluster.temporary_artifact || cluster.missing_artifact)) {
            output.append_original_rule_match("CLUSTER_ARTIFACT_NATIVE_BACKING", 80); // 1e829a3
            output.append_native_backing_evidence(method.name, method.backing_name240);
        }
    }
}
// Recovered: these are independent branches, so one method may append both rules.
// Score 85 has no artifact-eligibility gate. Score 80 ignores region flags and
// does not require a nonempty backing name. owner_module224 does not substitute
// for backing_name240 in either decision.
// Unresolved: exact evidence encoding remains behind the append contracts.
} // namespace ocean::reconstructed::minecraft_native_method_rules
