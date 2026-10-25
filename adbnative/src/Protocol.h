// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <cstdint>
#include <cstring>
#include <string>

// ============================================================================
//   ADB wire protocol (system/core/adb/protocol.txt)
//   24-byte little-endian header followed by data_length bytes of payload.
// ============================================================================

namespace adb::detail
{
    constexpr uint32_t A_CNXN = 0x4e584e43;
    constexpr uint32_t A_AUTH = 0x48545541;
    constexpr uint32_t A_OPEN = 0x4e45504f;
    constexpr uint32_t A_OKAY = 0x59414b4f;
    constexpr uint32_t A_CLSE = 0x45534c43;
    constexpr uint32_t A_WRTE = 0x45545257;
    constexpr uint32_t A_STLS = 0x534c5453;

    // 0x01000001 = data_check no longer required
    constexpr uint32_t A_VERSION = 0x01000001;
    constexpr uint32_t MAX_PAYLOAD = 1024 * 1024;

    constexpr uint32_t AUTH_TOKEN = 1;
    constexpr uint32_t AUTH_SIGNATURE = 2;
    constexpr uint32_t AUTH_RSAPUBLICKEY = 3;

    constexpr size_t HEADER_SIZE = 24;

    struct Message
    {
        uint32_t command = 0;
        uint32_t arg0 = 0;
        uint32_t arg1 = 0;
        std::string data;
    };

    // Header + payload, ready to send.
    std::string encodeMessage(const Message& m);

    // Parses a header; returns false if the magic does not match.
    bool decodeHeader(const uint8_t* header, Message& m, uint32_t& dataLength);

    std::string commandName(uint32_t command);

    // -------------------------------------------------------------------------
    // little-endian helpers (also used by the sync and shell protocols)
    // -------------------------------------------------------------------------
    inline void putU32(std::string& out, uint32_t v)
    {
        char b[4] = { char(v), char(v >> 8), char(v >> 16), char(v >> 24) };
        out.append(b, 4);
    }

    inline uint32_t getU32(const void* p)
    {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        return uint32_t(b[0]) | (uint32_t(b[1]) << 8) | (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
    }

    inline uint64_t getU64(const void* p)
    {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        return uint64_t(getU32(b)) | (uint64_t(getU32(b + 4)) << 32);
    }
}
