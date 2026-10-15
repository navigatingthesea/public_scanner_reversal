#include "../session/session_types.hpp"
// Recovered behavior summary:
//   Input: EventLog and netprofm service configurations from SCM.
//   Gate: EventLog matches start_type != 2; netprofm matches start_type == 4, even when the ignored
//         query result leaves a zeroed buffer.
//   Output: Emits the corresponding EventLog report and structured numeric detection.
//   Failure: Manager/service-open failure skips that check; all close results are ignored.

namespace ocean::reconstructed::shared_eventlog_service_checks {
using Handle=std::uint64_t;
struct QueryConfig {
    std::uint32_t service_type=0,start_type=0,error_control=0;
};
struct Contracts {
    virtual Handle original_open_sc_manager_null_machine_null_database(std::uint32_t access)=0;
    virtual Handle original_open_service_w(Handle,const ByteString&,std::uint32_t)=0;
    virtual void original_query_service_config_w_ignore_result(Handle,QueryConfig&,
                                       std::uint32_t buffer_size,std::uint32_t& bytes_needed)=0;
    virtual void original_close_service_handle_ignore_result(Handle)=0;
    virtual void append_original_eventlog_report(const ByteString&)=0;
    virtual void append_structured_detection(const ByteString&,const ByteString&,std::uint32_t)=0;
    virtual void register_original_panic_recovery(const ByteString&,const ByteString&)=0;
    virtual void reviewed_minint_check()=0;
    virtual void reviewed_maxsize_checks()=0;
};
void check_service(Contracts& runtime,bool eventlog) {
    runtime.register_original_panic_recovery(
        eventlog ? "DEventLogTamper_ServiceStart" : "DEventLogTamper_Netprofm",
        eventlog ? "Failed to check EventLog service start type" :
                   "Failed to check netprofm service start type");
    const auto manager=runtime.original_open_sc_manager_null_machine_null_database(1);
    if(manager==0) return;
    const auto service=runtime.original_open_service_w(manager,eventlog?"EventLog":"netprofm",1);
    if(service!=0) {
        QueryConfig configuration{};std::uint32_t bytes_needed=0;
        // Original allocates64-byte QUERY_SERVICE_CONFIGW buffer, no resizing/retry,
        // ignores BOOL/error/bytesNeeded and inspects zero-initialized start_type+4.
        runtime.original_query_service_config_w_ignore_result(service,configuration,0x40,bytes_needed);
        if(eventlog ? configuration.start_type!=2 : configuration.start_type==4) {
            runtime.append_original_eventlog_report(
                eventlog ?
                    "EventLog Tamper (Service Disabled):::Boot instance:::"
                    "The user disabled or modified the Windows EventLog service startup type" :
                    "EventLog Tamper (netprofm Disabled):::Boot instance:::"
                    "The user disabled the netprofm service to allow fully stopping the EventLog service");
            runtime.append_structured_detection("Detect",eventlog?"EventLog_StartType":"EventLog_Netprofm",configuration.start_type);
        }
        runtime.original_close_service_handle_ignore_result(service);
    }
    runtime.original_close_service_handle_ignore_result(manager);
}
void run(Contracts& runtime) { //PDTUOfU@1294000
    runtime.register_original_panic_recovery("DEventLogTamper","Main function execution failed");
    runtime.reviewed_minint_check();          //ifNTMek@1294080
    check_service(runtime,true);             //xUqTj@1294320
    runtime.reviewed_maxsize_checks();        //gnPgc@1294ea0
    check_service(runtime,false);            //b1w5@1295940
}
// Captured LazyProc descriptors prove advapi32 OpenSCManagerW,OpenServiceW,
// QueryServiceConfigW,CloseServiceHandle. No service writes/start/stop performed.
//20 original synthetic API cases returned: start2 alone accepted EventLog, start4
// alone flagsnetprofm, manager/service failures suppress, failed query+zero config
// causes EventLog false-positive finding0 but no netprofm finding. Close results
// ignored, service then manager order. Numeric uint32 kept typed in structured row.
// No service-state/process/event-log-generation checks; wording is scanner attribution.
// Recovery logger closure source is eventlog_recovery.cpp. VM-only C++ never run/compiled.
}
