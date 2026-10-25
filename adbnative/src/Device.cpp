// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "DeviceCore.h"
#include "Util.h"
#include "adb/Device.h"

#include <sstream>
#include <thread>

namespace adb
{
    using namespace detail;

    namespace detail
    {
        std::string trimRight(std::string s)
        {
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\0'))
                s.pop_back();
            return s;
        }
    }

    namespace
    {
        std::string serialFor(const std::string& host, int port)
        {
            // Same naming adb uses for local emulators it finds by port scan.
            bool local = host == "127.0.0.1" || host == "localhost" || host == "::1";
            if (local && port >= 5555 && port <= 5585 && (port % 2) == 1)
                return "emulator-" + std::to_string(port - 1);
            return host + ":" + std::to_string(port);
        }

        // Shell protocol v2 packet ids (system/core/adb/shell_protocol.h)
        constexpr char kIdStdout = 1;
        constexpr char kIdStderr = 2;
        constexpr char kIdExit = 3;
        constexpr char kIdCloseStdin = 4;
    }

    // =========================================================================
    // CONNECT
    // =========================================================================
    Device Device::connect(const std::string& serial, const ConnectOptions& options)
    {
        if (startsWith(serial, "emulator-"))
            return connect("127.0.0.1", std::stoi(serial.substr(9)) + 1, options);

        size_t colon = serial.rfind(':');
        if (colon != std::string::npos && serial.find(':') == colon)
            return connect(serial.substr(0, colon), std::stoi(serial.substr(colon + 1)), options);

        // [v6addr]:port
        if (!serial.empty() && serial[0] == '[')
        {
            size_t close = serial.find(']');
            if (close != std::string::npos)
            {
                int port = close + 2 < serial.size() ? std::stoi(serial.substr(close + 2)) : 5555;
                return connect(serial.substr(1, close - 1), port, options);
            }
        }

        return connect(serial, 5555, options);
    }

    Device Device::connect(const std::string& host, int port, const ConnectOptions& options)
    {
        auto core = std::make_shared<DeviceCore>();
        core->host = host;
        core->port = port;
        core->serial = serialFor(host, port);
        core->options = options;

        core->conn = Connection::create(host, port, options);
        core->info = core->conn->info();
        core->info.serial = core->serial;
        installReverseHandler(*core->conn, core->reverse);

        return Device(core);
    }

    void Device::reconnect(std::chrono::milliseconds timeout)
    {
        if (!core)
            throw AdbError("invalid device");

        {
            std::lock_guard<std::mutex> lock(core->mutex);
            if (core->conn)
                core->conn->close();
            core->conn.reset();
        }

        auto deadline = std::chrono::steady_clock::now() + timeout;
        std::string lastError;

        while (std::chrono::steady_clock::now() < deadline)
        {
            try
            {
                auto conn = Connection::create(core->host, core->port, core->options);
                installReverseHandler(*conn, core->reverse);

                std::lock_guard<std::mutex> lock(core->mutex);
                core->conn = conn;
                core->info = conn->info();
                core->info.serial = core->serial;
                return;
            }
            catch (const std::exception& e)
            {
                lastError = e.what();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        throw AdbError("reconnect to " + core->serial + " failed: " + lastError);
    }

    // =========================================================================
    // INFO
    // =========================================================================
    const DeviceInfo& Device::info() const
    {
        if (!core)
            throw AdbError("invalid device");
        return core->info;
    }

    bool Device::hasFeature(const std::string& feature) const
    {
        return core->connection()->hasFeature(feature);
    }

    bool Device::alive() const
    {
        if (!core)
            return false;
        std::lock_guard<std::mutex> lock(core->mutex);
        return core->conn && core->conn->alive();
    }

    Stream Device::openStream(const std::string& service)
    {
        return core->connection()->open(service);
    }

    // =========================================================================
    // SHELL
    // =========================================================================
    int Device::shellStream(const std::string& command, const OutputCallback& onStdout, const OutputCallback& onStderr)
    {
        auto conn = core->connection();

        if (!conn->hasFeature("shell_v2"))
        {
            // Legacy: one merged stream, no exit code.
            Stream s = conn->open("shell:" + command);
            char buffer[64 * 1024];
            while (size_t n = s.read(buffer, sizeof(buffer)))
            {
                if (onStdout && !onStdout(std::string_view(buffer, n)))
                    return -1;
            }
            return -1;
        }

        Stream s = conn->open("shell,v2,raw:" + command);

        // No stdin from us; close it so commands that read it don't hang.
        std::string closeStdin(1, kIdCloseStdin);
        putU32(closeStdin, 0);
        s.write(closeStdin);

        int exitCode = -1;
        std::string data;

        while (true)
        {
            // [u8 id][u32 length][payload]
            uint8_t header[5];
            size_t got = s.read(header, sizeof(header));
            if (got == 0)
                break;
            if (got < sizeof(header))
                s.readExact(header + got, sizeof(header) - got);

            uint32_t length = getU32(header + 1);
            data.resize(length);
            if (length)
                s.readExact(data.data(), length);

            switch (header[0])
            {
            case kIdStdout:
                if (onStdout && !onStdout(data))
                    return -1;
                break;
            case kIdStderr:
                if (onStderr && !onStderr(data))
                    return -1;
                break;
            case kIdExit:
                exitCode = length ? (uint8_t)data[0] : 0;
                break;
            default:
                break;
            }
        }

        return exitCode;
    }

    ShellResult Device::shell(const std::string& command)
    {
        ShellResult r;
        r.exitCode = shellStream(
            command,
            [&](std::string_view d) { r.out.append(d); return true; },
            [&](std::string_view d) { r.err.append(d); return true; });
        return r;
    }

    std::string Device::execOut(const std::string& command)
    {
        return openStream("exec:" + command).readAll();
    }

    std::string Device::getProp(const std::string& name)
    {
        return trimRight(shell("getprop " + shellQuote(name)).out);
    }

    std::map<std::string, std::string> Device::getProps()
    {
        // "[ro.build.version.sdk]: [34]"
        std::map<std::string, std::string> props;
        std::stringstream ss(shell("getprop").out);
        std::string line;
        while (std::getline(ss, line))
        {
            size_t k0 = line.find('[');
            size_t k1 = line.find("]: [");
            size_t v1 = line.rfind(']');
            if (k0 == std::string::npos || k1 == std::string::npos || v1 <= k1 + 3)
                continue;
            props[line.substr(k0 + 1, k1 - k0 - 1)] = line.substr(k1 + 4, v1 - k1 - 4);
        }
        return props;
    }

    int Device::logcat(const std::string& args, const OutputCallback& onOutput)
    {
        return shellStream("logcat " + args, onOutput, onOutput);
    }

    std::string Device::screencap()
    {
        std::string png = execOut("screencap -p");
        if (png.size() < 8 || png.compare(0, 8, "\x89PNG\r\n\x1a\n") != 0)
            throw AdbError("screencap failed: " + trimRight(png.substr(0, 200)));
        return png;
    }

    // =========================================================================
    // SYSTEM
    // =========================================================================
    void Device::reboot(const std::string& target)
    {
        Stream s = openStream("reboot:" + target);
        try
        {
            s.readAll();
        }
        catch (...)
        {
            // connection drops while the device goes down
        }
    }

    std::string Device::root()
    {
        return trimRight(openStream("root:").readAll());
    }

    std::string Device::unroot()
    {
        return trimRight(openStream("unroot:").readAll());
    }

    std::string Device::tcpip(int port)
    {
        return trimRight(openStream("tcpip:" + std::to_string(port)).readAll());
    }

    std::string Device::usb()
    {
        return trimRight(openStream("usb:").readAll());
    }

    std::string Device::remount()
    {
        // Newer adbd runs remount as a shell command (feature remount_shell).
        if (hasFeature("remount_shell"))
        {
            ShellResult r = shell("remount");
            std::string out = trimRight(r.out + r.err);
            if (r.exitCode != 0)
                throw AdbError("remount failed: " + out);
            return out;
        }
        return trimRight(openStream("remount:").readAll());
    }

    std::string Device::disableVerity()
    {
        return trimRight(openStream("disable-verity:").readAll());
    }

    std::string Device::enableVerity()
    {
        return trimRight(openStream("enable-verity:").readAll());
    }
}
