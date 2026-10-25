// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <filesystem>
#include <string>

namespace adb::detail
{
    // Library strings are UTF-8; convert for local file APIs.
    inline std::filesystem::path toPath(const std::string& utf8)
    {
        return std::filesystem::path(std::u8string(utf8.begin(), utf8.end()));
    }

    inline std::string fromPath(const std::filesystem::path& p)
    {
        std::u8string s = p.u8string();
        return std::string(s.begin(), s.end());
    }

    inline bool startsWith(const std::string& s, const std::string& prefix)
    {
        return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
    }

    // Quote for the device's /system/bin/sh.
    inline std::string shellQuote(const std::string& s)
    {
        std::string out = "'";
        for (char c : s)
        {
            if (c == '\'')
                out += "'\\''";
            else
                out += c;
        }
        out += "'";
        return out;
    }
}
