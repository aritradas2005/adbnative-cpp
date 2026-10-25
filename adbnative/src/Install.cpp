// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "DeviceCore.h"
#include "Util.h"
#include "adb/Device.h"

#include <fstream>
#include <sstream>

namespace adb
{
    using namespace detail;

    namespace
    {
        // How we reach the package manager, best first.
        enum class PmChannel
        {
            AbbExec,    // abb_exec:package\0install\0...  (Android 10+, binder direct)
            Cmd,        // exec:cmd package install ...     (Android 7+)
            Legacy,     // push to /data/local/tmp + pm install
        };

        PmChannel pmChannel(Connection& conn)
        {
            if (conn.hasFeature("abb_exec"))
                return PmChannel::AbbExec;
            if (conn.hasFeature("cmd"))
                return PmChannel::Cmd;
            return PmChannel::Legacy;
        }

        std::string pmService(PmChannel channel, const std::vector<std::string>& args)
        {
            std::string service;
            if (channel == PmChannel::AbbExec)
            {
                service = "abb_exec:package";
                for (auto& a : args)
                    service += '\0' + a;
            }
            else
            {
                service = "exec:cmd package";
                for (auto& a : args)
                    service += " " + shellQuote(a);
            }
            return service;
        }

        void streamFile(Stream& s, const std::filesystem::path& file)
        {
            std::ifstream in(file, std::ios::binary);
            if (!in)
                throw AdbError("cannot open " + fromPath(file));

            std::string buffer(s.maxPayload(), '\0');
            while (true)
            {
                in.read(buffer.data(), buffer.size());
                std::streamsize n = in.gcount();
                if (n <= 0)
                    break;
                s.write(buffer.data(), (size_t)n);
            }
        }

        std::string checkSuccess(const std::string& what, const std::string& output)
        {
            std::string out = trimRight(output);
            if (out.find("Success") == std::string::npos)
                throw AdbError(what + " failed: " + out);
            return out;
        }
    }

    // =========================================================================
    // INSTALL
    // =========================================================================
    std::string Device::install(const std::string& apkPath, const std::vector<std::string>& args)
    {
        std::filesystem::path apk = toPath(apkPath);
        if (!std::filesystem::is_regular_file(apk))
            throw AdbError("APK not found: " + apkPath);

        auto conn = core->connection();
        PmChannel channel = pmChannel(*conn);

        if (channel == PmChannel::Legacy)
        {
            std::string remote = "/data/local/tmp/" + fromPath(apk.filename());
            push(apkPath, remote);

            std::string cmd = "pm install";
            for (auto& a : args)
                cmd += " " + shellQuote(a);
            cmd += " " + shellQuote(remote);

            ShellResult r = shell(cmd);
            shell("rm -f " + shellQuote(remote));
            return checkSuccess("install", r.out + r.err);
        }

        // Streamed install: pm reads exactly -S bytes from us.
        std::vector<std::string> a{ "install" };
        a.insert(a.end(), args.begin(), args.end());
        a.push_back("-S");
        a.push_back(std::to_string(std::filesystem::file_size(apk)));

        Stream s = conn->open(pmService(channel, a));
        streamFile(s, apk);
        return checkSuccess("install", s.readAll());
    }

    std::string Device::installMultiple(const std::vector<std::string>& apkPaths, const std::vector<std::string>& args)
    {
        if (apkPaths.empty())
            throw AdbError("install-multiple: no APKs given");

        auto conn = core->connection();
        PmChannel channel = pmChannel(*conn);
        if (channel == PmChannel::Legacy)
            throw AdbError("install-multiple needs Android 7+ (cmd package)");

        uint64_t total = 0;
        for (auto& p : apkPaths)
        {
            if (!std::filesystem::is_regular_file(toPath(p)))
                throw AdbError("APK not found: " + p);
            total += std::filesystem::file_size(toPath(p));
        }

        // 1) create session: "Success: created install session [1234]"
        std::vector<std::string> createArgs{ "install-create" };
        createArgs.insert(createArgs.end(), args.begin(), args.end());
        createArgs.push_back("-S");
        createArgs.push_back(std::to_string(total));

        std::string created = checkSuccess("install-create", conn->open(pmService(channel, createArgs)).readAll());
        size_t l = created.find('[');
        size_t r = created.find(']', l);
        if (l == std::string::npos || r == std::string::npos)
            throw AdbError("install-create: no session id in '" + created + "'");
        std::string session = created.substr(l + 1, r - l - 1);

        try
        {
            // 2) write each APK into the session
            for (size_t i = 0; i < apkPaths.size(); i++)
            {
                std::filesystem::path apk = toPath(apkPaths[i]);
                std::string name = std::to_string(i) + "_" + fromPath(apk.filename());

                Stream s = conn->open(pmService(channel, {
                    "install-write", "-S", std::to_string(std::filesystem::file_size(apk)), session, name, "-" }));
                streamFile(s, apk);
                checkSuccess("install-write " + name, s.readAll());
            }

            // 3) commit
            return checkSuccess("install-commit", conn->open(pmService(channel, { "install-commit", session })).readAll());
        }
        catch (...)
        {
            try
            {
                conn->open(pmService(channel, { "install-abandon", session })).readAll();
            }
            catch (...)
            {
            }
            throw;
        }
    }

    // =========================================================================
    // UNINSTALL / LIST
    // =========================================================================
    std::string Device::uninstall(const std::string& packageName, bool keepData)
    {
        auto conn = core->connection();
        PmChannel channel = pmChannel(*conn);

        std::vector<std::string> a{ "uninstall" };
        if (keepData)
            a.push_back("-k");
        a.push_back(packageName);

        if (channel == PmChannel::Legacy)
        {
            ShellResult r = shell(std::string("pm uninstall ") + (keepData ? "-k " : "") + shellQuote(packageName));
            return checkSuccess("uninstall", r.out + r.err);
        }

        return checkSuccess("uninstall", conn->open(pmService(channel, a)).readAll());
    }

    std::vector<std::string> Device::listPackages(const std::string& flags)
    {
        ShellResult r = shell("pm list packages " + flags);

        std::vector<std::string> packages;
        std::stringstream ss(r.out);
        std::string line;
        while (std::getline(ss, line))
        {
            line = trimRight(line);
            if (startsWith(line, "package:"))
                packages.push_back(line.substr(8));
        }
        return packages;
    }
}
