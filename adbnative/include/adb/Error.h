// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <stdexcept>
#include <string>

namespace adb
{
    // Every failure in the library is reported as AdbError. When the device
    // rejected something, what() carries the device's own message.
    class AdbError : public std::runtime_error
    {
    public:
        explicit AdbError(const std::string& message)
            : std::runtime_error(message)
        {
        }
    };
}
