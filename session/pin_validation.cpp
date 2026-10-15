#include "session_types.hpp"
#include <array>

namespace ocean::reconstructed {
struct SessionValidationContracts {
    struct Request {
        std::uint64_t opaque;
    };
    struct Response {
        std::uint64_t opaque;
    };

    virtual ~SessionValidationContracts() = default;
    virtual void store_string(std::uint64_t rva, const ByteString&) = 0;
    virtual void store_byte(std::uint64_t rva, std::uint8_t) = 0;
    virtual std::uint8_t load_byte(std::uint64_t rva) = 0;
    virtual void lock_session_mutex() = 0;    // global 0x577a000
    virtual void unlock_session_mutex() = 0;
    virtual SessionCache& shared_cache() = 0; // global 0x5731820, 136-byte record
    virtual ByteString sha256_hex(const ByteString&) = 0;
    virtual ByteString request_i_hex_digest(const ByteString&) = 0; // EN8GHL.NmSN9nK0
    virtual ByteString request_h_value() = 0; // JgTvca8i66A.VJ3Gcn
    virtual ByteString hardware_id() = 0;
    virtual ByteString marshal_request_map_ignoring_error(
        const std::map<ByteString, ByteString>&) = 0;
    virtual bool new_post_request(
        const ByteString& url,
        const ByteString& body,
        Request&) = 0;
    virtual void set_captured_headers(Request) = 0; // literals at draft 0x10b08a0
    virtual bool send_request(
        Request,
        std::int64_t timeout_nanoseconds,
        Response&) = 0;
    virtual void defer_close_body(Response) = 0;
    virtual std::int64_t status_code(Response) = 0;
    virtual bool response_has_request_and_url(Response) = 0;
    virtual ByteString response_request_url_string(Response) = 0;
    virtual bool read_all_body(Response, ByteString&) = 0;
    virtual ByteString decode_response(
        const ByteString& encoded,
        const ByteString& hex_key) = 0;
    virtual SessionResponse& shared_response() = 0; // global 0x57333c0
    virtual bool unmarshal_into_existing_response(
        const ByteString&,
        SessionResponse&) = 0;
    virtual void exit_process(std::int32_t code) = 0;
};

template<class Fields>
ValidatedSession session_outputs(const ByteString& pin, const Fields& fields) {
    return {
        fields.field_f,
        pin,
        fields.field_cs,
        fields.field_rh,
        fields.field_hl,
        fields.field_sus,
        fields.field_l,
    };
}

std::vector<ByteString> split_on_slash(const ByteString& value) {
    std::vector<ByteString> result;
    std::size_t start = 0;
    for (;;) {
        const auto separator = value.find('/', start);
        if (separator == ByteString::npos) {
            result.push_back(value.substr(start));
            return result;
        }
        result.push_back(value.substr(start, separator - start));
        start = separator + 1;
    }
}

bool supported_game(const ByteString& value) {
    constexpr std::array<const char*, 14> games = {
        "dayz", "scum", "altv", "ragemp", "roblox", "bedrock", "redm",
        "sanandreas", "fivem", "java", "rust", "cod", "freefire", "hytale",
    };
    for (const auto* game : games)
        if (value == game) return true;
    return false;
}

// JgTvca8i66A.DRKJpjH@0x10b07a0
bool session_abort_flag(SessionValidationContracts& runtime) {
    runtime.lock_session_mutex();
    const bool value = runtime.load_byte(0x5779ead) != 0;
    runtime.unlock_session_mutex();
    return value;
}

// JgTvca8i66A.GRgCSz@0x10b08a0
ValidatedSession validate_pin_session(
    SessionValidationContracts& runtime,
    const ByteString& pin) {
    // Recovered: publish the raw pin to both globals before consulting cache.
    runtime.store_string(0x572b890, pin);
    runtime.store_string(0x572ba10, pin);

    runtime.lock_session_mutex();
    runtime.store_byte(0x5779ead, 0);
    auto& cache = runtime.shared_cache();
    if (cache.pin_input == pin && !cache.retained_fields.field_f.empty()) {
        const auto cached = cache.retained_fields;
        runtime.unlock_session_mutex();
        runtime.store_string(0x572b880, cached.game_selector);
        runtime.store_string(0x572b8d0, cached.field_f);
        return session_outputs(pin, cached);
    }
    runtime.unlock_session_mutex();

    const auto body_key = runtime.sha256_hex(
        pin + "6biQw.07g:f!#Nf8TvYw-kN_Y4U-4!");
    const auto request_i = runtime.request_i_hex_digest(pin);
    const auto request_h = runtime.request_h_value();
    const auto hardware_id = runtime.hardware_id();
    if (hardware_id.empty()) return {};

    const std::map<ByteString, ByteString> payload = {
        {"i", request_i},
        {"h", request_h},
        {"w", hardware_id},
    };
    const auto request_body =
        runtime.marshal_request_map_ignoring_error(payload);

    SessionValidationContracts::Request request;
    const auto url =
        ByteString("https://api.anticheat.ac/validations/validate-pin/") + pin + "/";
    if (!runtime.new_post_request(url, request_body, request)) {
        runtime.exit_process(222);
        return {};
    }

    runtime.set_captured_headers(request);
    SessionValidationContracts::Response response;
    if (!runtime.send_request(request, 60000000000LL, response)) {
        runtime.exit_process(223);
        return {};
    }
    runtime.defer_close_body(response);

    if (runtime.status_code(response) == 417) {
        runtime.lock_session_mutex();
        runtime.store_byte(0x5779ead, 1);
        runtime.shared_cache() = {};
        runtime.unlock_session_mutex();

        if (runtime.load_byte(0x5779eab) != 0) return {};
        runtime.exit_process(18);
        return {};
    }

    if (!runtime.response_has_request_and_url(response)) {
        runtime.exit_process(224);
        return {};
    }

    const auto url_parts = split_on_slash(
        runtime.response_request_url_string(response));
    if (url_parts.size() < 2) {
        runtime.exit_process(225);
        return {};
    }

    ByteString base_url;
    for (std::size_t index = 0; index + 2 < url_parts.size(); ++index) {
        if (index != 0) base_url += '/';
        base_url += url_parts[index];
    }
    base_url += '/';

    const auto expected = runtime.sha256_hex(
        base_url + "qD1E3W#Vo0iG~Iz+2y*3KlM.xB!nS;@9pZ5LrA4v/pT%7wXf,-<U8T");
    if (expected !=
        "a012166d7a1c51d0e4e930f8c1d0c0bf659f50e5145ac982d2afcf1b1a72bb00") {
        runtime.exit_process(226);
        return {};
    }

    ByteString encoded_body;
    if (!runtime.read_all_body(response, encoded_body)) {
        runtime.exit_process(227);
        return {};
    }

    const auto decoded_body = runtime.decode_response(encoded_body, body_key);
    auto& value = runtime.shared_response();
    // Recovered: the global response object is not cleared before unmarshal.
    if (!runtime.unmarshal_into_existing_response(decoded_body, value)) {
        runtime.exit_process(228);
        return {};
    }
    if (!value.success || !supported_game(value.game_selector)) {
        runtime.exit_process(229);
        return {};
    }

    runtime.store_string(0x572b880, value.game_selector);
    runtime.store_string(0x572b8d0, value.field_f);
    runtime.lock_session_mutex();
    runtime.shared_cache() = {
        pin,
        {value.field_f, value.game_selector, value.field_cs, value.field_rh,
         value.field_hl, value.field_l, value.field_sus},
    };
    runtime.unlock_session_mutex();
    return session_outputs(pin, value);
}

// Input: a PIN. Cache hit requires exact PIN equality and nonempty field_f.
// Cache miss posts JSON-like keys i/h/w to the PIN endpoint with a 60-second
// timeout, decodes the response with SHA256(pin+salt), accepts only success plus
// one of 14 exact game selectors, publishes two globals, and caches seven fields.
//
// Failure behavior: empty HWID returns an empty session. Request construction,
// transport, URL integrity, body read, decode/unmarshal, and response validation
// terminate with codes 222..229 as shown. HTTP 417 sets abort byte 0x5779ead,
// clears cache, then either returns when 0x5779eab is set or exits 18.
// Crypto, headers, codecs, transport, and mutex/global storage remain contracts.
}
