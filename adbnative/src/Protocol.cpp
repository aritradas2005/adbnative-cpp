// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "Protocol.h"

namespace adb::detail
{
    std::string encodeMessage(const Message& m)
    {
        uint32_t check = 0;
        for (unsigned char c : m.data)
            check += c;

        std::string out;
        out.reserve(HEADER_SIZE + m.data.size());
        putU32(out, m.command);
        putU32(out, m.arg0);
        putU32(out, m.arg1);
        putU32(out, (uint32_t)m.data.size());
        putU32(out, check);              // ignored by modern adbd, required by very old ones
        putU32(out, m.command ^ 0xFFFFFFFF);
        out += m.data;
        return out;
    }

    bool decodeHeader(const uint8_t* header, Message& m, uint32_t& dataLength)
    {
        m.command = getU32(header);
        m.arg0 = getU32(header + 4);
        m.arg1 = getU32(header + 8);
        dataLength = getU32(header + 12);
        uint32_t magic = getU32(header + 20);
        return magic == (m.command ^ 0xFFFFFFFF);
    }

    std::string commandName(uint32_t command)
    {
        switch (command)
        {
        case A_CNXN: return "CNXN";
        case A_AUTH: return "AUTH";
        case A_OPEN: return "OPEN";
        case A_OKAY: return "OKAY";
        case A_CLSE: return "CLSE";
        case A_WRTE: return "WRTE";
        case A_STLS: return "STLS";
        default:     return "0x" + std::to_string(command);
        }
    }
}
