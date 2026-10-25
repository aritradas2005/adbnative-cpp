// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "DeviceCore.h"
#include "Util.h"
#include "adb/Device.h"
#include "adb/Forward.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <list>
#include <set>
#include <thread>
#include <vector>

namespace adb
{
    using namespace detail;

    namespace
    {
        // Copies bytes both ways between a local socket and a device stream
        // until either side closes. Closes the socket when done.
        void pump(SOCKET sock, Stream stream)
        {
            std::thread toSocket([sock, stream]() mutable
            {
                std::vector<char> buffer(64 * 1024);
                try
                {
                    while (size_t n = stream.read(buffer.data(), buffer.size()))
                        sendAll(sock, buffer.data(), n);
                }
                catch (...)
                {
                }
                ::shutdown(sock, SD_BOTH);
            });

            std::vector<char> buffer(stream.maxPayload());
            while (true)
            {
                int r = recv(sock, buffer.data(), (int)buffer.size(), 0);
                if (r <= 0)
                    break;

                try
                {
                    stream.write(buffer.data(), (size_t)r);
                }
                catch (...)
                {
                    break;
                }
            }

            stream.close();                  // ADB has no half-close
            toSocket.join();
            closesocket(sock);
        }

        bool hexPrefixed(const std::string& s)
        {
            return s.size() >= 4 && std::all_of(s.begin(), s.begin() + 4, [](char c) { return isxdigit((unsigned char)c); });
        }

        // "OKAY" ["%04x" payload], "FAIL" "%04x" message, or just "%04x" payload
        // (reverse:list-forward sends no OKAY).
        std::string parseHostReply(const std::string& what, const std::string& reply)
        {
            if (startsWith(reply, "FAIL"))
                throw AdbError(what + " failed: " + (reply.size() > 8 ? reply.substr(8) : reply));

            std::string rest = reply;
            if (startsWith(rest, "OKAY"))
                rest = rest.substr(4);
            else if (!hexPrefixed(rest))
                throw AdbError(what + ": unexpected reply '" + reply + "'");

            if (startsWith(rest, "OKAY"))
                rest = rest.substr(4);
            if (hexPrefixed(rest))
                return rest.substr(4, std::stoul(rest.substr(0, 4), nullptr, 16));
            return "";
        }
    }

    namespace detail
    {
        // =====================================================================
        // FORWARD: local listener -> device service
        // =====================================================================
        class ForwardImpl
        {
        public:
            ForwardImpl(std::shared_ptr<DeviceCore> core, int localPort, std::string remote)
                : core(std::move(core)), remote(std::move(remote)), port(localPort)
            {
                listener = listenLoopback(port);
                acceptor = std::thread([this] { acceptLoop(); });
            }

            ~ForwardImpl()
            {
                stop();
            }

            int localPort() const { return port; }

            void stop()
            {
                if (stopping.exchange(true))
                    return;

                closesocket(listener);       // unblocks accept()
                acceptor.join();

                std::list<Client> all;
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    for (auto& c : clients)
                        ::shutdown(c.sock, SD_BOTH);
                    all.swap(clients);
                }

                for (auto& c : all)
                    c.thread.join();
            }

        private:
            struct Client
            {
                SOCKET sock;
                std::thread thread;
                std::shared_ptr<std::atomic<bool>> done;
            };

            void acceptLoop()
            {
                while (!stopping)
                {
                    SOCKET s = accept(listener, nullptr, nullptr);
                    if (s == INVALID_SOCKET)
                        break;

                    BOOL noDelay = TRUE;
                    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&noDelay, sizeof(noDelay));

                    std::lock_guard<std::mutex> lock(mutex);
                    reapFinished();

                    auto done = std::make_shared<std::atomic<bool>>(false);
                    clients.push_back({ s, std::thread([this, s, done]
                    {
                        try
                        {
                            pump(s, core->connection()->open(remote));
                        }
                        catch (...)
                        {
                            closesocket(s);  // device refused the service
                        }
                        *done = true;
                    }), done });
                }
            }

            void reapFinished()
            {
                for (auto it = clients.begin(); it != clients.end();)
                {
                    if (*it->done)
                    {
                        it->thread.join();
                        it = clients.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            std::shared_ptr<DeviceCore> core;
            std::string remote;
            int port;
            SOCKET listener = INVALID_SOCKET;
            std::thread acceptor;
            std::atomic<bool> stopping{ false };

            std::mutex mutex;
            std::list<Client> clients;
        };

        // =====================================================================
        // REVERSE: device opens "tcp:<port>" -> connect to 127.0.0.1:<port>
        // =====================================================================
        void installReverseHandler(Connection& conn, std::shared_ptr<ReverseRegistry> registry)
        {
            conn.setIncomingHandler([registry](const std::string& service, Stream stream)
            {
                if (!registry->allowed(service) || !startsWith(service, "tcp:"))
                    return false;

                SOCKET s;
                try
                {
                    s = connectTcp("127.0.0.1", std::stoi(service.substr(4)), std::chrono::milliseconds(1000));
                }
                catch (...)
                {
                    return false;
                }

                std::thread([s, stream] { pump(s, stream); }).detach();
                return true;
            });
        }
    }

    // =========================================================================
    // PortForward
    // =========================================================================
    PortForward& PortForward::operator=(PortForward&& other) noexcept
    {
        if (this != &other)
        {
            stop();
            impl = std::move(other.impl);
        }
        return *this;
    }

    PortForward::~PortForward()
    {
        stop();
    }

    int PortForward::localPort() const
    {
        return impl ? impl->localPort() : 0;
    }

    void PortForward::stop()
    {
        if (impl)
        {
            impl->stop();
            impl.reset();
        }
    }

    // =========================================================================
    // DEVICE API
    // =========================================================================
    PortForward Device::forward(int localPort, const std::string& remoteSpec)
    {
        if (!core)
            throw AdbError("invalid device");
        return PortForward(std::make_shared<ForwardImpl>(core, localPort, remoteSpec));
    }

    int Device::reverse(const std::string& remoteSpec, int localPort)
    {
        std::string local = "tcp:" + std::to_string(localPort);
        {
            std::lock_guard<std::mutex> lock(core->reverse->mutex);
            core->reverse->byRemote[remoteSpec] = local;
        }

        try
        {
            std::string reply = openStream("reverse:forward:" + remoteSpec + ";" + local).readAll();
            std::string port = parseHostReply("reverse " + remoteSpec, reply);

            if (!port.empty())
            {
                // tcp:0 -> the device picked a port
                std::lock_guard<std::mutex> lock(core->reverse->mutex);
                core->reverse->byRemote.erase(remoteSpec);
                core->reverse->byRemote["tcp:" + port] = local;
                return std::stoi(port);
            }

            return startsWith(remoteSpec, "tcp:") ? std::stoi(remoteSpec.substr(4)) : 0;
        }
        catch (...)
        {
            std::lock_guard<std::mutex> lock(core->reverse->mutex);
            core->reverse->byRemote.erase(remoteSpec);
            throw;
        }
    }

    void Device::removeReverse(const std::string& remoteSpec)
    {
        parseHostReply("reverse --remove " + remoteSpec,
                       openStream("reverse:killforward:" + remoteSpec).readAll());

        std::lock_guard<std::mutex> lock(core->reverse->mutex);
        core->reverse->byRemote.erase(remoteSpec);
    }

    void Device::removeAllReverse()
    {
        parseHostReply("reverse --remove-all", openStream("reverse:killforward-all").readAll());

        std::lock_guard<std::mutex> lock(core->reverse->mutex);
        core->reverse->byRemote.clear();
    }

    std::string Device::listReverse()
    {
        return trimRight(parseHostReply("reverse --list", openStream("reverse:list-forward").readAll()));
    }
}
