// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <string>

namespace adb::detail
{
    // WSAStartup once for the whole process.
    void ensureWinsock();

    std::string socketErrorText(int code);

    // Connects with a timeout; throws AdbError.
    SOCKET connectTcp(const std::string& host, int port, std::chrono::milliseconds timeout);

    // Listens on 127.0.0.1:port (0 = any free port); returns the socket, sets port.
    SOCKET listenLoopback(int& port);

    void sendAll(SOCKET s, const void* data, size_t size);

    // ------------------------------------------------------------------------
    // TCP transport to adbd
    // ------------------------------------------------------------------------
    class TcpTransport
    {
    public:
        TcpTransport(const std::string& host, int port, std::chrono::milliseconds timeout);
        ~TcpTransport();

        TcpTransport(const TcpTransport&) = delete;
        TcpTransport& operator=(const TcpTransport&) = delete;

        void writeAll(const void* data, size_t size);
        void readExact(void* data, size_t size);

        // true if data is ready before the timeout expires
        bool waitReadable(std::chrono::milliseconds timeout);

        // Unblocks a thread sitting in readExact().
        void shutdown();

    private:
        SOCKET sock = INVALID_SOCKET;
    };
}
