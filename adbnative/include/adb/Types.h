// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace adb
{
    struct ConnectOptions
    {
        // Private key used for RSA auth. Empty = %USERPROFILE%\.android\adbkey,
        // the same key Google's adb uses, so already-authorized devices just work.
        // Created (with its .pub) if it does not exist.
        std::string keyPath;

        std::chrono::milliseconds connectTimeout{ 3000 };

        // How long to wait for the handshake, including the user tapping
        // "Allow USB debugging" when the key is not yet trusted.
        std::chrono::milliseconds authTimeout{ 30000 };

        // How long to wait for the device to accept a service (OPEN -> OKAY).
        std::chrono::milliseconds openTimeout{ 10000 };
    };

    // Everything the device told us in its CNXN banner.
    struct DeviceInfo
    {
        std::string serial;      // "emulator-5554" or "host:port"
        std::string host;
        int port = 0;

        std::string product;     // ro.product.name
        std::string model;       // ro.product.model
        std::string device;      // ro.product.device
        std::vector<std::string> features;

        uint32_t protocolVersion = 0;
        uint32_t maxPayload = 0;
        std::string banner;      // raw banner, e.g. "device::ro.product.name=...;features=..."
    };

    struct ShellResult
    {
        std::string out;
        std::string err;
        int exitCode = -1;       // -1 when the device has no shell_v2 (exit code unknown)
    };

    struct FileStat
    {
        uint32_t mode = 0;       // POSIX st_mode
        uint64_t size = 0;
        int64_t mtime = 0;       // seconds since epoch

        bool isDirectory() const { return (mode & 0170000) == 0040000; }
        bool isRegular() const { return (mode & 0170000) == 0100000; }
        bool isSymlink() const { return (mode & 0170000) == 0120000; }
    };

    struct DirEntry
    {
        std::string name;
        FileStat stat;
    };

    // Called during push/pull. file = file currently being transferred,
    // done/total are bytes for the whole operation.
    using ProgressCallback = std::function<void(const std::string& file, uint64_t done, uint64_t total)>;

    // Receives streamed output. Return false to stop the command.
    using OutputCallback = std::function<bool(std::string_view chunk)>;
}
