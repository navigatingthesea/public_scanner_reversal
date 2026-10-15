#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: Application.evtx events, captured 64-byte rule records, and the global baseline.
//   Gate: Requires exact EventID string 1000, a parsed timestamp strictly after baseline, then
//         case-lowered joined EventData substring matches.
//   Output: Emits one PowerShell-bypass report and MIERDAPSE row for every matched term.
//   Failure: Open failure reports once; marshal/unmarshal/time failures skip an event and stream
//            close errors are ignored.

namespace ocean::reconstructed::shared_evtx_bypass_flow {
struct Time {
    std::uint64_t wall,ext,location;
};
struct Rule {
    ByteString label;
    std::vector<ByteString> terms;
}; //raw original stride64, projection0/16
struct Event {
    ByteString id_value,system_time;
    std::vector<ByteString> event_data;
};
struct RawEvent {
    std::uint64_t captured_provider_identity;
};
struct Json {ByteString bytes;bool error;};
struct ParsedEvent {Event event;bool error;};
struct ParsedTime {Time value;bool error;};
struct Stream {
    std::uint64_t identity;
    bool error;
};
struct Contracts {
    virtual Stream original_evtx_open(const ByteString&)=0; // EVWteO.FTCsDJwXHK; see windows_evtx_reader.cpp
    virtual bool original_channel_next(Stream&,RawEvent&)=0; // Events channel; producer reconstructed in windows_evtx_reader.cpp
    virtual void original_stream_close_ignore_result(Stream&)=0;
    virtual void report_original_open_error()=0;
    virtual Json original_json_marshal_event(const RawEvent&)=0;
    virtual ParsedEvent original_json_unmarshal_event200(const ByteString&)=0;
    virtual ByteString original_unicode_trim_space(const ByteString&)=0;
    virtual ByteString original_unicode_lowercase(const ByteString&)=0;
    virtual ParsedTime original_parse_go_time(const ByteString&,const ByteString&)=0;
    virtual bool original_time_after(Time,Time)=0;
    virtual std::vector<ByteString> reviewed_item_matcher(const ByteString&,const std::vector<ByteString>&)=0;
    virtual void append_original_report(const ByteString&)=0;
    virtual void append_structured_detection(const std::vector<ByteString>&)=0;
    virtual ByteString reviewed_event_file_choice()=0;
    virtual Time original_global_event_baseline()=0;
    virtual std::vector<Rule> original_shared_rule_records64()=0;
};
bool scan(Contracts& runtime,const ByteString& path,const std::vector<Rule>& rules,Time baseline) {
    auto stream=runtime.original_evtx_open(path);
    if(stream.error) {runtime.report_original_open_error();return false;}
    bool found=false;RawEvent raw{};
    while(runtime.original_channel_next(stream,raw)) {
        const auto json=runtime.original_json_marshal_event(raw);
        if(json.error) continue;
        const auto decoded=runtime.original_json_unmarshal_event200(json.bytes);
        if(decoded.error || decoded.event.id_value!="1000") continue;
        const auto timestamp=runtime.original_parse_go_time(
            "2006-01-02T15:04:05.999999999Z07:00",
            runtime.original_unicode_trim_space(decoded.event.system_time));
        if(timestamp.error || !runtime.original_time_after(timestamp.value,baseline)) continue;
        ByteString text;
        for(std::size_t k=0;k<decoded.event.event_data.size();++k) {
            if(k) text+=" | ";text+=decoded.event.event_data[k];
        }
        text=runtime.original_unicode_lowercase(text);
        for(const auto& rule:rules) {
            const auto matches=runtime.reviewed_item_matcher(text,rule.terms);
            for(const auto& matched:matches) {
                runtime.append_original_report(rule.label+
                    ":::Boot instance:::A PowerShell bypass command was executed");
                runtime.append_structured_detection({"Detect","MIERDAPSE",matched,json.bytes});
            }
            if(!matches.empty()) found=true;
        }
    }
    runtime.original_stream_close_ignore_result(stream);return found;
}
void run(Contracts& runtime) { //N8huiY7Y@12a05c0
    scan(runtime,runtime.reviewed_event_file_choice(),runtime.original_shared_rule_records64(),
         runtime.original_global_event_baseline()); //return bool discarded
}
// Event Go struct36474c0size200 proven tags: Event.EventData.Data[]string and Binary,
// Event.System.EventID.Value,TimeCreated.SystemTime; otherChannel/Computer/Execution/
// Provider/EventRecordID fields decode but do not gate this body. No numeric EventID
// coercion: exact4-byte1000. No direct Provider/Channel/ApplicationError filter.
//8 original caller fixtures returned under explicit synthetic stream/JSON/time/
//matcher providers. They validate gates/reportappend, NOT the EVTX reader/JSON codec.
// JSON text included in structured finding preserves whole marshaled event object.
// Native reader decoding/concurrency/close/open-error behavior is in windows_evtx_reader.cpp;
// shared rules are projected in captured_event_rules.cpp.
// The raw file/chunk/event producer is reconstructed in windows_evtx_reader.cpp; this body
// retains only application event-field/codec contracts.
// VM-only readable C++ never compiled/run.
}
