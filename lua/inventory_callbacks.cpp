#include "query_records.hpp"

namespace ocean::reconstructed::lua_review {
struct ServiceRecord { // @0x377e120, 88 bytes
    ByteString name;
    ByteString display_name;
    std::uint32_t status = 0;
    ByteString status_text;
    std::uint32_t service_type = 0;
    bool running = false;
    std::uint32_t pid = 0;
    std::uint32_t start_type = 0;
    ByteString binary_path;
};

struct InventoryCallbackContracts {
    using State = std::uint64_t;
    using Value = std::uint64_t;
    using Manager = std::uint64_t;

    virtual ~InventoryCallbackContracts() = default;
    virtual QueryError enumerate_services(std::vector<ServiceRecord>&) = 0;
    virtual QueryError open_service_manager(
        std::uint64_t machine,
        std::uint64_t database,
        std::uint32_t access,
        Manager&) = 0; // N2a7FDI@4cc1e0
    virtual void close_service_manager(Manager) = 0; // L3vo96bGBc@4ccb20
    virtual void original_service_configuration(
        Manager,
        const ByteString&,
        std::uint32_t& start_type,
        ByteString& binary_path) = 0; // jQFH6cwi@1eee2c0
    virtual std::int64_t push_service_records(
        State, const std::vector<ServiceRecord>&) = 0;
    virtual QueryError installed_software(
        Value&, bool& has_backing_storage) = 0;
    virtual Value empty_nonnil_installed_software_slice() = 0;
    virtual QueryError smb_connections(Value&) = 0;
    virtual std::int64_t push_original_go_value(State, Value) = 0;
    virtual std::int64_t push_original_inventory_error(
        State, std::uint32_t original_callback, const QueryError&) = 0;
};

// @0x1f3ae60
std::int64_t services_callback(
    InventoryCallbackContracts& runtime,
    InventoryCallbackContracts::State state) {
    std::vector<ServiceRecord> rows;
    const auto error = runtime.enumerate_services(rows);
    if (error)
        return runtime.push_original_inventory_error(state, 0x1f3ae60, error);

    InventoryCallbackContracts::Manager manager = 0;
    const auto manager_error = runtime.open_service_manager(0, 0, 1, manager);
    struct CloseManager {
        InventoryCallbackContracts& runtime;
        InventoryCallbackContracts::Manager manager;
        bool acquired;
        ~CloseManager() {
            if (acquired) runtime.close_service_manager(manager);
        }
    } close{runtime, manager, !manager_error};

    for (auto& row : rows) {
        row.start_type = 0;
        row.binary_path.clear();
        if (!manager_error) {
            // Recovered: configuration-query errors are handled inside this
            // provider and do not remove the already-enumerated service.
            runtime.original_service_configuration(
                manager, row.name, row.start_type, row.binary_path);
        }
    }
    return runtime.push_service_records(state, rows);
}

// @0x1f3be00
std::int64_t installed_software_callback(
    InventoryCallbackContracts& runtime,
    InventoryCallbackContracts::State state) {
    InventoryCallbackContracts::Value records = 0;
    bool has_backing_storage = false;
    const auto error = runtime.installed_software(records, has_backing_storage);
    if (error)
        return runtime.push_original_inventory_error(state, 0x1f3be00, error);
    if (!has_backing_storage)
        records = runtime.empty_nonnil_installed_software_slice();
    return runtime.push_original_go_value(state, records);
}

// @0x1f3eaa0
std::int64_t smb_connections_callback(
    InventoryCallbackContracts& runtime,
    InventoryCallbackContracts::State state) {
    InventoryCallbackContracts::Value records = 0;
    const auto error = runtime.smb_connections(records);
    if (error)
        return runtime.push_original_inventory_error(state, 0x1f3eaa0, error);
    return runtime.push_original_go_value(state, records);
}

// Services returns base enumeration even when opening SCM fails; enrichment is
// then blank. InstalledSoftware normalizes nil to allocated-empty. SMB connections
// are passed through. Only each primary collector's error becomes a Lua error.
}
