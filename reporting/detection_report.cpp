#include "../../common/review_contracts.hpp"

namespace ocean::reconstructed {
// UAy9caHUbZ.D79x1l8X@0xf32580
void submit_detection_report(
    RuntimeContracts& runtime,
    const ByteString& reason,
    const ByteString& supplied_endpoint) {
    // Recovered: all providers run before the proxy-identity branch, in this order.
    const auto peer = runtime.describe_peer_certificate();
    const auto hardware_id = runtime.hwid_provider(false);
    const auto pc_start = runtime.pc_start_provider();
    const auto processes = runtime.running_processes_provider();
    const auto discord = runtime.discord_provider();
    const auto anydesk = runtime.anydesk_boolean_provider();
    const auto screenshot = runtime.screenshot_provider();

    Report report;
    report["pc_start"] = pc_start;
    report["screenshot"] = screenshot;
    report["anydesk_ss"] = anydesk;
    report["discord"] = discord;
    report["hwid"] = hardware_id;
    report["pin"] = reason;
    report["game"] = runtime.globals().game;
    report["RUNNINGP"] = processes;
    report["SSL"] = peer.description;

    if (peer.mitmproxy_identity) {
        runtime.encode_and_send_report(
            "https://api.anticheat.ac/validations/r/d", report);
        runtime.exit_process(77);
        // Recovered: os.Exit is terminal. Returning here would violate the flow.
    } else {
        runtime.encode_and_send_report(supplied_endpoint, report);
    }
}

// Input: a reason string stored under `pin`, plus a caller-supplied endpoint.
// Output: one encoded report containing host/process/contact/screenshot data and
// the observed peer-certificate description. A mitmproxy issuer/subject reroutes
// the report to the fixed validation endpoint and terminates with status 77.
//
// Unresolved: the initial dial, TLS handshake, certificate acquisition, provider
// failure handling, serialization, and network send remain RuntimeContracts.
// The fifth caller register word was observed but has no proven parameter role.
}
