// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include "Device.h"

#include <vector>

namespace adb
{
    // Ports where common Windows emulators expose adbd on 127.0.0.1:
    // Android Studio / LDPlayer 5555-5585 (odd), MuMu 7555 / 16384+32n,
    // Nox 62001 / 62025+, MEmu 21503+10n, BlueStacks 5555+10n.
    std::vector<int> defaultEmulatorPorts();

    // adb devices — probes the ports in parallel and connects to every adbd
    // that answers. Devices that refuse auth are skipped.
    std::vector<Device> findEmulators(const ConnectOptions& options = {},
                                      const std::vector<int>& ports = defaultEmulatorPorts());
}
