#include "efi_evidence_types.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
// Recovered behavior summary:
//   Input: Binary UEFI device-path nodes.
//   Gate: Walks length-tagged nodes, decodes supported filepath/media forms, and searches the first
//         uppercase GPT={...} token.
//   Output: Returns a readable path, node labels, drive type, and partition GUID attribution.
//   Failure: Malformed/truncated nodes stop according to recovered bounds behavior; GUID text is
//            not shape-validated.

namespace ocean::reconstructed::efi_device_path {

struct ParsedPath {
    ByteString path;
    std::vector<ByteString> nodes;
};

static std::uint16_t u16(const ByteString& bytes, std::size_t offset) {
    return std::uint16_t(std::uint8_t(bytes[offset])) |
           (std::uint16_t(std::uint8_t(bytes[offset + 1])) << 8);
}

static std::uint32_t u32(const ByteString& bytes, std::size_t offset) {
    return u16(bytes, offset) |
           (std::uint32_t(u16(bytes, offset + 2)) << 16);
}

static ByteString format(const char* pattern,
                         unsigned long long a = 0,
                         unsigned long long b = 0,
                         unsigned long long c = 0) {
    char output[256]{};
    std::snprintf(output, sizeof(output), pattern, a, b, c);
    return output;
}

static ByteString upper_ascii(ByteString text) {
    for (char& character : text) {
        if (character >= 'a' && character <= 'z') {
            character = char(character - 'a' + 'A');
        }
    }
    return text;
}

static ByteString hex_lower(const ByteString& bytes) {
    constexpr char alphabet[] = "0123456789abcdef";
    ByteString output;
    for (const std::uint8_t byte : bytes) {
        output += alphabet[byte >> 4];
        output += alphabet[byte & 15];
    }
    return output;
}

static ByteString guid(const ByteString& bytes, bool upper_tail) {
    if (bytes.size() != 16) {
        return {};
    }

    char head[64]{};
    std::snprintf(head, sizeof(head), "{%08X-%04X-%04X-%02X%02X-",
                  u32(bytes, 0), u16(bytes, 4), u16(bytes, 6),
                  std::uint8_t(bytes[8]), std::uint8_t(bytes[9]));
    auto tail = hex_lower(bytes.substr(10, 6));
    if (upper_tail) {
        tail = upper_ascii(tail);
    }
    return ByteString(head) + tail + "}";
}

static ByteString utf16le(const ByteString& bytes) {
    // uqfV2n discards one trailing odd byte, decodes UTF-16 with Go's standard
    // replacement behavior, then converts runes to UTF-8.
    ByteString output;
    const auto append = [&](std::uint32_t rune) {
        if (rune <= 0x7f) {
            output += char(rune);
        } else if (rune <= 0x7ff) {
            output += char(0xc0 | (rune >> 6));
            output += char(0x80 | (rune & 63));
        } else if (rune <= 0xffff) {
            output += char(0xe0 | (rune >> 12));
            output += char(0x80 | ((rune >> 6) & 63));
            output += char(0x80 | (rune & 63));
        } else {
            output += char(0xf0 | (rune >> 18));
            output += char(0x80 | ((rune >> 12) & 63));
            output += char(0x80 | ((rune >> 6) & 63));
            output += char(0x80 | (rune & 63));
        }
    };

    for (std::size_t offset = 0; offset + 1 < bytes.size(); offset += 2) {
        auto rune = u16(bytes, offset);
        if (rune >= 0xd800 && rune <= 0xdbff && offset + 3 < bytes.size()) {
            const auto low = u16(bytes, offset + 2);
            if (low >= 0xdc00 && low <= 0xdfff) {
                append(0x10000 + ((rune - 0xd800) << 10) + (low - 0xdc00));
                offset += 2;
                continue;
            }
        }
        if (rune >= 0xd800 && rune <= 0xdfff) {
            rune = 0xfffd;
        }
        append(rune);
    }
    return output;
}

static ByteString generic(std::uint8_t type,
                          std::uint8_t subtype,
                          std::size_t payload_size) {
    char output[96]{};
    std::snprintf(output, sizeof(output), "Node(T=%02Xh,ST=%02Xh,Len=%zu)",
                  type, subtype, payload_size);
    return output;
}

ParsedPath parse(const ByteString& input) { // fcRCoHpyiIX @ 0x12cc940
    ParsedPath result;
    std::size_t cursor = 0;
    while (cursor + 4 <= input.size()) {
        const auto type = std::uint8_t(input[cursor]);
        const auto subtype = std::uint8_t(input[cursor + 1]);
        const auto node_length = u16(input, cursor + 2);
        if (node_length < 4 || node_length > input.size() - cursor) {
            break;
        }

        const auto payload = input.substr(cursor + 4, node_length - 4);
        ByteString label;
        if (type == 0x7f && subtype == 0xff) {
            result.nodes.push_back("End");
            return result;
        }

        if (type == 1 && subtype == 1 && payload.size() >= 2) {
            label = format("PCI(Dev=0x%llX,Fn=0x%llX)",
                           std::uint8_t(payload[1]), std::uint8_t(payload[0]));
        } else if (type == 2 && subtype == 1 && payload.size() >= 8) {
            label = format("ACPI(PNP%04llX,UID=%llu)",
                           u32(payload, 0) >> 16, u32(payload, 4));
        } else if (type == 2 && subtype == 2 && payload.size() >= 16) {
            label = format("ACPI_EX(PNP%04llX,UID=%llu)",
                           u32(payload, 0) >> 16, u32(payload, 4));
        } else if (type == 3 && subtype == 1 && payload.size() >= 2) {
            static const std::array<ByteString, 2> channels{"Primary", "Secondary"};
            static const std::array<ByteString, 2> devices{"Master", "Slave"};
            const auto channel = std::uint8_t(payload[0]);
            const auto device = std::uint8_t(payload[1]);
            label = "ATAPI(" + (channel < 2 ? channels[channel] : ByteString{}) +
                    "," + (device < 2 ? devices[device] : ByteString{}) + ")";
        } else if (type == 3 && subtype == 2 && payload.size() >= 4) {
            label = format("SCSI(Target=%llu,LUN=%llu)",
                           u16(payload, 0), u16(payload, 2));
        } else if (type == 3 && subtype == 5 && payload.size() >= 2) {
            label = format("USB(Port=%llu,Intf=%llu)",
                           std::uint8_t(payload[0]), std::uint8_t(payload[1]));
        } else if (type == 3 && subtype == 10 && payload.size() >= 16) {
            label = "Vendor(" + guid(payload.substr(0, 16), false) + ")";
        } else if (type == 3 && subtype == 15 && payload.size() >= 6) {
            char output[64]{};
            std::snprintf(output, sizeof(output),
                          "MAC(%02X:%02X:%02X:%02X:%02X:%02X)",
                          std::uint8_t(payload[0]), std::uint8_t(payload[1]),
                          std::uint8_t(payload[2]), std::uint8_t(payload[3]),
                          std::uint8_t(payload[4]), std::uint8_t(payload[5]));
            label = output;
        } else if (type == 3 && subtype == 18 && payload.size() >= 2) {
            label = format("SATA(Port=%llu,Mux=0x%llX,LUN=%llu)",
                           u16(payload, 0),
                           payload.size() < 6 ? 0 : u16(payload, 2),
                           payload.size() < 6 ? 0 : u16(payload, 4));
        } else if (type == 3 && subtype == 23 && payload.size() >= 4) {
            label = format("NVMe(NSID=0x%llX)", u32(payload, 0));
        } else if (type == 3 && subtype == 24) {
            label = "URI(" + payload + ")"; // raw bytes, including NUL
        } else if (type == 3 && subtype == 29 && payload.size() >= 1) {
            label = format("eMMC(Slot=%llu)", std::uint8_t(payload[0]));
        } else if (type == 3 && subtype == 31 && payload.size() >= 1) {
            label = format("SD(Slot=%llu)", std::uint8_t(payload[0]));
        } else if (type == 4 && subtype == 1 && payload.size() >= 38) {
            const auto signature_type = std::uint8_t(payload[37]);
            label = "HD(Part=" + std::to_string(u32(payload, 0)) + ",GPT=" +
                    (signature_type == 2
                         ? guid(payload.substr(20, 16), true)
                         : ByteString{}) +
                    ")";
        } else if (type == 4 && subtype == 2) {
            label = "CDROM";
        } else if (type == 4 && subtype == 3 && payload.size() >= 16) {
            label = "MediaVendor(" + guid(payload.substr(0, 16), false) + ")";
        } else if (type == 4 && subtype == 4) {
            auto path = utf16le(payload);
            while (!path.empty() && path.back() == 0) {
                path.pop_back();
            }
            result.path = path;
            label = "File(" + path + ")";
        } else if (type == 4 && subtype == 5 && payload.size() >= 16) {
            label = "MediaProtocol(" + guid(payload.substr(0, 16), false) + ")";
        } else if (type == 4 && subtype == 6) {
            label = "FirmwareFile";
        } else if (type == 4 && subtype == 7) {
            label = "FirmwareVolume";
        } else if (type == 4 && subtype == 9) {
            label = "RAMDisk";
        } else {
            label = generic(type, subtype, payload.size());
        }

        result.nodes.push_back(label);
        cursor += node_length;
    }
    return result; // malformed/short tail retains earlier path and nodes
}

ByteString drive_type(const std::vector<ByteString>& nodes) { // gLKfqeb @ 0x12cc600
    for (const ByteString prefix :
         {"USB(", "SATA(", "NVMe(", "ATAPI(", "SCSI(", "eMMC(", "SD("}) {
        for (const auto& node : nodes) {
            if (node.starts_with(prefix)) {
                return prefix.substr(0, prefix.size() - 1);
            }
        }
    }
    for (const auto& node : nodes) {
        if (node == "CDROM") {
            return "CDROM";
        }
    }
    for (const auto& node : nodes) {
        if (node == "RAMDisk") {
            return "RAMDisk";
        }
    }
    return "Unknown"; // case-sensitive; bus-family priority beats node order
}

ByteString partition_guid(
    const std::vector<ByteString>& nodes) { // nLiGLuU5 @ 0x12cc560
    // Captured regexp: GPT=\\{([0-9A-Fa-f-]+)\\}. Search in node order and
    // return the first capture after ASCII uppercasing.
    for (const auto& node : nodes) {
        const ByteString marker = "GPT={";
        auto begin = node.find(marker);
        if (begin == ByteString::npos) {
            continue;
        }
        begin += marker.size();
        const auto end = node.find('}', begin);
        if (end == ByteString::npos || end == begin) {
            continue;
        }
        const auto value = node.substr(begin, end - begin);
        const bool valid_characters = std::all_of(
            value.begin(), value.end(),
            [](unsigned char character) {
                return std::isxdigit(character) || character == '-';
            });
        if (valid_characters) {
            return upper_ascii(value);
        }
    }
    return {};
    // There is no GUID length/shape validation: {abc} and {---} match;
    // lowercase gpt= does not. Multiple matches use the first.
}

// 103 original decoder fixtures and 26 attribution fixtures returned. GUID
// construction, UTF-16 conversion, and ASCII uppercase ran through original
// functions; allocation/copy and primitive formatting remain standard-library
// review abstractions.

}  // namespace ocean::reconstructed::efi_device_path
