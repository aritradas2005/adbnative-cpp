// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "Net.h"
#include "adb/Discovery.h"

#include <algorithm>
#include <future>

namespace adb
{
    std::vector<int> defaultEmulatorPorts()
    {
        std::vector<int> ports;

        for (int p = 5555; p <= 5585; p += 2)       // Android Studio, LDPlayer, BlueStacks
            ports.push_back(p);
        ports.push_back(7555);                       // MuMu 6
        for (int i = 0; i < 16; i++)                 // MuMu 12
            ports.push_back(16384 + 32 * i);
        ports.push_back(62001);                      // Nox
        for (int p = 62025; p <= 62040; p++)
            ports.push_back(p);
        for (int i = 0; i < 10; i++)                 // MEmu
            ports.push_back(21503 + 10 * i);

        std::sort(ports.begin(), ports.end());
        ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
        return ports;
    }

    std::vector<Device> findEmulators(const ConnectOptions& options, const std::vector<int>& ports)
    {
        // Quick TCP probe first so closed ports don't cost a full handshake timeout.
        ConnectOptions probe = options;
        probe.connectTimeout = std::min(options.connectTimeout, std::chrono::milliseconds(300));

        std::vector<std::future<Device>> pending;
        for (int port : ports)
        {
            pending.push_back(std::async(std::launch::async, [port, probe]
            {
                return Device::connect("127.0.0.1", port, probe);
            }));
        }

        std::vector<Device> found;
        for (auto& f : pending)
        {
            try
            {
                found.push_back(f.get());
            }
            catch (...)
            {
                // nothing there, or it refused us
            }
        }
        return found;
    }
}
