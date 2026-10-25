// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include "Connection.h"
#include "adb/Error.h"

#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace adb::detail
{
    // Local targets the device is allowed to open back to us (adb reverse).
    // Anything else the device asks for is refused, like adb does.
    struct ReverseRegistry
    {
        std::mutex mutex;
        std::map<std::string, std::string> byRemote;   // device spec -> local spec ("tcp:8000")

        bool allowed(const std::string& local)
        {
            std::lock_guard<std::mutex> lock(mutex);
            for (auto& [remote, l] : byRemote)
                if (l == local)
                    return true;
            return false;
        }
    };

    struct DeviceCore
    {
        std::string host;
        int port = 0;
        std::string serial;
        ConnectOptions options;

        std::mutex mutex;
        std::shared_ptr<Connection> conn;
        DeviceInfo info;
        std::shared_ptr<ReverseRegistry> reverse = std::make_shared<ReverseRegistry>();

        std::shared_ptr<Connection> connection()
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!conn)
                throw AdbError("device not connected");
            return conn;
        }

        ~DeviceCore()
        {
            if (conn)
                conn->close();
        }
    };

    // Forward.cpp: hooks device-initiated OPENs up to local TCP ports.
    void installReverseHandler(Connection& conn, std::shared_ptr<ReverseRegistry> registry);

    std::string trimRight(std::string s);
}
