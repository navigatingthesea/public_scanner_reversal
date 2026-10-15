#include "../lua/query_records.hpp"
#include <functional>
#include <map>
namespace ocean::reconstructed::hashed_inventory_review {
// Recovered: enumerate service names and process names, hash each salted name,
// and store digest -> PID-text mappings in a persistent map. Later process rows
// overwrite equal service digests; collection failure still signals completion.
using ByteString = lua_review::ByteString;
using Error = lua_review::QueryError;
struct HashInventoryGlobals {
    std::map<ByteString, ByteString> name_hash_to_pid;
}; // 5727bb8; map is not cleared here
struct HashInventoryContracts {
    using Channel = std::uint64_t;
    using ServiceManager = std::uint64_t;
    using Process = std::uint64_t;
    struct Panic {
        std::uint64_t type = 0, data = 0;
    };
    struct Defers {
        virtual ~Defers() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~HashInventoryContracts() = default;
    virtual void original_timed_void_scope(const std::function<void()> &) = 0;
    virtual Channel buffered_byte_channel(std::size_t) = 0;
    virtual void spawn_goroutine(const std::function<void()> &) = 0;
    virtual void receive_byte(Channel) = 0;
    virtual void send_original_completion_byte(Channel, bool success) = 0;
    virtual void original_recovery_scope(const std::function<void(Defers &)> &,
                                         const std::function<void(Panic)> &) = 0;
    virtual void log_original_recovered_panic(Panic) = 0; // Crash + original label@3e2bf00
    virtual Error connect_local_service_manager(ServiceManager &) = 0; // EPd.Q1kU7t("","")
    virtual void disconnect_manager(ServiceManager) = 0;
    virtual Error list_service_names(ServiceManager, std::vector<ByteString> &) = 0;
    virtual std::uint32_t query_service_pid(const ByteString &) = 0; // NN9p33oaT below
    virtual Error list_processes_with_original_background_context(std::vector<Process> &) = 0;
    virtual std::int32_t process_pid(Process) = 0;
    virtual Error process_name_with_original_background_context(Process, ByteString &) = 0;
    virtual ByteString original_sha256_lower_hex(const ByteString &) = 0;
};
// Exact 58 UTF-8 bytes returned by constant getter@e35140, including c2 bf.
ByteString original_inventory_hash_suffix() {
    return "*1_S\xc2\xbf"
           "2*-1|CMQP{}Q+S(1+..,.129211319'IDS93<ZX,z.-129z-.z19";
}
// Worker@f23940. Service names and process names share one namespace, so later
// process entries can overwrite a service entry with the same salted digest.
void hashed_name_inventory_worker(HashInventoryContracts &r, HashInventoryGlobals &globals,
                                  HashInventoryContracts::Channel channel) {
    r.original_recovery_scope(
        [&](HashInventoryContracts::Defers &defers) {
            const auto suffix = original_inventory_hash_suffix();
            HashInventoryContracts::ServiceManager manager = 0;
            if (r.connect_local_service_manager(manager)) {
                r.send_original_completion_byte(channel, false);
                return;
            }
            defers.add([&r, manager] { r.disconnect_manager(manager); });
            std::vector<ByteString> services;
            if (r.list_service_names(manager, services)) {
                r.send_original_completion_byte(channel, false);
                return;
            }
            for (const auto &name : services) {
                const auto pid = r.query_service_pid(name); // failure0 still produces a stored "0"
                globals.name_hash_to_pid[r.original_sha256_lower_hex(name + suffix)] =
                    std::to_string(pid);
            }
            std::vector<HashInventoryContracts::Process> processes;
            if (r.list_processes_with_original_background_context(processes)) {
                r.send_original_completion_byte(channel, false);
                return;
            }
            for (const auto process : processes) {
                const auto pid = r.process_pid(process);
                ByteString name;
                if (r.process_name_with_original_background_context(process, name))
                    continue;
                if (name.find("svchost") != ByteString::npos)
                    continue; // case-sensitive substring, not exact basename
                globals.name_hash_to_pid[r.original_sha256_lower_hex(name + suffix)] =
                    std::to_string(pid);
            }
            r.send_original_completion_byte(channel, true);
        },
        [&](HashInventoryContracts::Panic panic) {
            r.log_original_recovered_panic(panic);
            r.send_original_completion_byte(channel, false);
        });
}
// Outer@f23840 ignores the received completion-byte value.
void collect_hashed_name_inventory(HashInventoryContracts &r, HashInventoryGlobals &globals) {
    r.original_timed_void_scope([&] {
        const auto channel = r.buffered_byte_channel(1);
        r.spawn_goroutine(
            [&r, &globals, channel] { hashed_name_inventory_worker(r, globals, channel); });
        r.receive_byte(channel);
    });
}
} // namespace ocean::reconstructed::hashed_inventory_review
