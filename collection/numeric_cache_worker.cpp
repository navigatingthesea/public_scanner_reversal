#include "../lua/query_records.hpp"
#include <functional>
#include <cmath>
namespace ocean::reconstructed::numeric_cache_review {
// Recovered: parse colon-separated numeric records, compute the original SSE2
// expression, retain transformed strings in input order, and refresh a shared
// cache through a worker channel. Short records panic; parse failures contribute zero.
using ByteString = lua_review::ByteString;
using Error = lua_review::QueryError;
struct StringSlice {
    bool backing_pointer_present = false;
    std::vector<ByteString> values;
};
struct NumericGlobals {
    StringSlice raw_values, processed_values;
}; // 572e2c0/c8/d0 and572e2e0/e8/f0
struct NumericContracts {
    using Channel = std::uint64_t;
    using LockedBuffer = std::uint64_t;
    struct Panic {
        std::uint64_t type = 0, data = 0;
    };
    struct Defers {
        virtual ~Defers() = default;
        virtual void add(const std::function<void()> &) = 0;
    };
    virtual ~NumericContracts() = default;
    virtual void original_timed_void_scope(const std::function<void()> &) = 0;
    virtual Channel buffered_slice_channel(std::size_t) = 0;
    virtual Channel buffered_byte_channel(std::size_t) = 0;
    virtual void spawn_goroutine(const std::function<void()> &) = 0;
    virtual StringSlice receive_slice(Channel) = 0;
    virtual void receive_byte_ignoring_value(Channel) = 0;
    virtual void send_slice(Channel, const StringSlice &) = 0;
    virtual void send_completion_byte(Channel, bool) = 0;
    virtual void original_recovery_scope(const std::function<void(Defers &)> &,
                                         const std::function<void(Panic)> &) = 0;
    virtual void log_recovered(const ByteString &label, Panic) = 0;
    virtual void log_recovered_original_label_descriptor(std::uint32_t label_rva, Panic) = 0;
    [[noreturn]] virtual void original_panic_bounds() = 0;
    virtual Error original_parse_float64(const ByteString &, double &) = 0;
    virtual double
    original_go_sin(double) = 0; // math.bjgGI6@2551a0; captured sine polynomial/zero/sign flow
    virtual ByteString
    original_format_six_decimals(double) = 0; // fmt.Sprintf("%.6f",value), includes NaN/Inf cases
    virtual LockedBuffer
    new_locked_buffer_from_bytes(std::vector<std::uint8_t> &) = 0; // 10a8100, moves/wipes source
    virtual ByteString copy_locked_bytes_to_go_string(LockedBuffer) = 0;
    virtual void destroy_locked_buffer(LockedBuffer) = 0;
    virtual void original_append_string(StringSlice &, const ByteString &) = 0;
    virtual StringSlice
    original_signed_time_response_worker() = 0; // Pe_57zSmjst2@10acee0; not yet implemented here
};
std::vector<ByteString> split_colons(const ByteString &value) {
    std::vector<ByteString> fields;
    std::size_t start = 0;
    for (;;) {
        const auto at = value.find(':', start);
        if (at == ByteString::npos) {
            fields.push_back(value.substr(start));
            return fields;
        }
        fields.push_back(value.substr(start, at - start));
        start = at + 1;
    }
}
double parse_field_or_zero(NumericContracts &r, const ByteString &field) {
    double value = 0;
    if (r.original_parse_float64(field, value))
        return 0;
    return value;
}
// cClur8j.func1@10aeba0. Short records panic AFTER parsing each preceding
// field; extra fields are ignored. Zero division/NaN/Inf are not rejected.
void numeric_slice_worker(NumericContracts &r, NumericContracts::Channel channel,
                          const StringSlice &input) {
    r.original_recovery_scope(
        [&](NumericContracts::Defers &defers) {
            StringSlice output; // originalnil slice
            for (const auto &record : input.values) {
                const auto fields = split_colons(record);
                if (fields.empty())
                    r.original_panic_bounds();
                const double a = parse_field_or_zero(r, fields[0]);
                if (fields.size() < 2)
                    r.original_panic_bounds();
                const double b = parse_field_or_zero(r, fields[1]);
                if (fields.size() < 3)
                    r.original_panic_bounds();
                const double c = parse_field_or_zero(r, fields[2]);
                if (fields.size() < 4)
                    r.original_panic_bounds();
                const double d = parse_field_or_zero(r, fields[3]);
                // Original SSE2 order: MUL a*60, DIV b/c, ADD, then ADD to d.
                const double angle = d + ((a * 60.0) + (b / c));
                double sum = 0.0;
                for (std::int64_t i = 1; i < 1000000; ++i)
                    sum = sum + r.original_go_sin(angle * double(i)) / std::sqrt(double(i));
                const auto formatted = r.original_format_six_decimals(sum);
                std::vector<std::uint8_t> bytes(formatted.begin(), formatted.end());
                const auto locked = r.new_locked_buffer_from_bytes(bytes);
                if (locked != 0) {
                    defers.add([&r, locked] { r.destroy_locked_buffer(locked); });
                    r.original_append_string(output, r.copy_locked_bytes_to_go_string(locked));
                }
            }
            r.send_slice(channel, output); // all locked buffers destroyed AFTER sending, LIFO
        },
        [&](NumericContracts::Panic panic) {
            r.log_recovered("mathd", panic);
            r.send_slice(channel, {});
        });
}
// cClur8j@10aeaa0; worker receives a copied input-slice header.
StringSlice process_numeric_slice(NumericContracts &r, const StringSlice &input) {
    const auto channel = r.buffered_slice_channel(1);
    r.spawn_goroutine([&r, channel, input] { numeric_slice_worker(r, channel, input); });
    return r.receive_slice(channel);
}
// Bmisqy.func1@10ac8e0. Cache validity checks backing pointer, NOT length.
void refresh_numeric_cache_worker(NumericContracts &r, NumericGlobals &globals,
                                  NumericContracts::Channel channel) {
    r.original_recovery_scope(
        [&](NumericContracts::Defers &) {
            if (!globals.raw_values.backing_pointer_present) {
                globals.raw_values = r.original_signed_time_response_worker();
                globals.processed_values = process_numeric_slice(r, globals.raw_values);
            }
            r.send_completion_byte(channel, true);
        },
        [&](NumericContracts::Panic panic) {
            r.log_recovered("RDE", panic);
            r.send_completion_byte(channel, false);
        });
}
// Bmisqy@10ac7e0: no timeout, originalcompletion-byte value discarded.
void refresh_numeric_cache(NumericContracts &r, NumericGlobals &globals) {
    r.original_timed_void_scope([&] {
        const auto channel = r.buffered_byte_channel(1);
        r.spawn_goroutine(
            [&r, &globals, channel] { refresh_numeric_cache_worker(r, globals, channel); });
        r.receive_byte_ignoring_value(channel);
    });
}
} // namespace ocean::reconstructed::numeric_cache_review
