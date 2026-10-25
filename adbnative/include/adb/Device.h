// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include "Error.h"
#include "Forward.h"
#include "Stream.h"
#include "Types.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace adb
{
    namespace detail
    {
        struct DeviceCore;
    }

    // A connection straight to a device's adbd (no adb.exe / adb server).
    // Copies share the same connection; it closes when the last copy goes away.
    // All methods are safe to call from several threads at once.
    class Device
    {
    public:
        // "emulator-5554" (-> 127.0.0.1:5555), "host:port" or "host" (port 5555).
        static Device connect(const std::string& serial, const ConnectOptions& options = {});
        static Device connect(const std::string& host, int port, const ConnectOptions& options = {});

        Device() = default;
        bool valid() const { return core != nullptr; }

        // =====================================================================
        // INFO
        // =====================================================================
        const DeviceInfo& info() const;
        const std::string& serial() const { return info().serial; }
        bool hasFeature(const std::string& feature) const;
        bool alive() const;                  // false once the device dropped the connection

        // Drop the connection and connect again (after root/unroot/tcpip or a reboot).
        void reconnect(std::chrono::milliseconds timeout = std::chrono::seconds(30));

        // Raw access to any device service, e.g. "shell,v2,pty:" or "localabstract:foo".
        Stream openStream(const std::string& service);

        // =====================================================================
        // SHELL
        // =====================================================================
        // adb shell <command>  — stdout, stderr and exit code (shell protocol v2).
        ShellResult shell(const std::string& command);

        // Streams output as it arrives; returns the exit code. Callbacks return
        // false to stop the command early (exit code is then -1).
        int shellStream(const std::string& command, const OutputCallback& onStdout,
                        const OutputCallback& onStderr = {});

        // adb exec-out <command>  — binary-clean stdout (screencap, tar, ...).
        std::string execOut(const std::string& command);

        std::string getProp(const std::string& name);
        std::map<std::string, std::string> getProps();

        // adb logcat <args>, e.g. logcat("-d -v brief", cb). Returns logcat's exit code.
        int logcat(const std::string& args, const OutputCallback& onOutput);

        // adb exec-out screencap -p  — PNG bytes.
        std::string screencap();

        // =====================================================================
        // FILES (sync protocol)
        // =====================================================================
        bool exists(const std::string& remotePath);
        FileStat stat(const std::string& remotePath);                 // follows symlinks
        std::vector<DirEntry> list(const std::string& remoteDir);     // without "." and ".."

        // adb push / adb pull — files or whole directories.
        // Pushing into an existing remote directory puts the item inside it, like adb.
        void push(const std::string& localPath, const std::string& remotePath,
                  const ProgressCallback& progress = {});
        void pull(const std::string& remotePath, const std::string& localPath,
                  const ProgressCallback& progress = {});

        // In-memory variants.
        void pushData(const std::string& data, const std::string& remotePath, uint32_t mode = 0644);
        std::string pullData(const std::string& remotePath);

        // =====================================================================
        // PACKAGES
        // =====================================================================
        // adb install [args] <apk>. Returns the package manager's output; throws on failure.
        std::string install(const std::string& apkPath, const std::vector<std::string>& args = { "-r" });

        // adb install-multiple [args] <apks...> (base + split APKs in one session).
        std::string installMultiple(const std::vector<std::string>& apkPaths,
                                    const std::vector<std::string>& args = { "-r" });

        // adb uninstall [-k] <package>
        std::string uninstall(const std::string& packageName, bool keepData = false);

        // pm list packages [flags] — package names only. flags e.g. "-3" for third-party.
        std::vector<std::string> listPackages(const std::string& flags = "");

        // =====================================================================
        // SYSTEM
        // =====================================================================
        // adb reboot [bootloader|recovery|sideload|...]. The connection drops afterwards.
        void reboot(const std::string& target = "");

        // These restart adbd; call reconnect() afterwards. Return the device's message.
        std::string root();
        std::string unroot();
        std::string tcpip(int port);
        std::string usb();

        std::string remount();
        std::string disableVerity();
        std::string enableVerity();

        // =====================================================================
        // PORT FORWARDING
        // =====================================================================
        // adb forward tcp:<localPort> <remoteSpec>. localPort 0 picks a free port
        // (see PortForward::localPort()). remoteSpec: "tcp:8080",
        // "localabstract:chrome_devtools_remote", "jdwp:<pid>", ...
        PortForward forward(int localPort, const std::string& remoteSpec);

        // adb reverse <remoteSpec> tcp:<localPort>. Connections the device makes
        // to remoteSpec are tunnelled to 127.0.0.1:localPort on this PC.
        // Returns the device-side port (useful with "tcp:0").
        int reverse(const std::string& remoteSpec, int localPort);
        void removeReverse(const std::string& remoteSpec);
        void removeAllReverse();
        std::string listReverse();

    private:
        explicit Device(std::shared_ptr<detail::DeviceCore> core)
            : core(std::move(core))
        {
        }

        std::shared_ptr<detail::DeviceCore> core;
    };
}
