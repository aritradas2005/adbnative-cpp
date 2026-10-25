// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "Net.h"
#include "adb/Error.h"

#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

namespace adb::detail
{
    void ensureWinsock()
    {
        struct WinsockInit
        {
            WinsockInit()
            {
                WSADATA wsa;
                if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
                    throw AdbError("WSAStartup failed");
            }

            ~WinsockInit()
            {
                WSACleanup();
            }
        };

        static WinsockInit init;
    }

    std::string socketErrorText(int code)
    {
        char* msg = nullptr;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, code, 0, (LPSTR)&msg, 0, nullptr);

        std::string text = msg ? msg : "";
        if (msg)
            LocalFree(msg);

        while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == '.'))
            text.pop_back();

        return text + " (" + std::to_string(code) + ")";
    }

    SOCKET connectTcp(const std::string& host, int port, std::chrono::milliseconds timeout)
    {
        ensureWinsock();

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* result = nullptr;
        std::string portStr = std::to_string(port);
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result) != 0)
            throw AdbError("cannot resolve host " + host);

        std::string lastError = "no address";

        for (addrinfo* ai = result; ai; ai = ai->ai_next)
        {
            SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s == INVALID_SOCKET)
                continue;

            // non-blocking connect so we can apply the timeout
            u_long nonBlocking = 1;
            ioctlsocket(s, FIONBIO, &nonBlocking);

            int rc = ::connect(s, ai->ai_addr, (int)ai->ai_addrlen);
            if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
            {
                fd_set writeSet, errorSet;
                FD_ZERO(&writeSet);
                FD_ZERO(&errorSet);
                FD_SET(s, &writeSet);
                FD_SET(s, &errorSet);

                timeval tv;
                tv.tv_sec = (long)(timeout.count() / 1000);
                tv.tv_usec = (long)(timeout.count() % 1000) * 1000;

                rc = select(0, nullptr, &writeSet, &errorSet, &tv);
                if (rc > 0 && FD_ISSET(s, &writeSet))
                {
                    rc = 0;
                }
                else
                {
                    int err = 0;
                    int len = sizeof(err);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
                    lastError = rc == 0 ? "timed out" : socketErrorText(err);
                    rc = SOCKET_ERROR;
                }
            }
            else if (rc == SOCKET_ERROR)
            {
                lastError = socketErrorText(WSAGetLastError());
            }

            if (rc == 0)
            {
                nonBlocking = 0;
                ioctlsocket(s, FIONBIO, &nonBlocking);

                BOOL noDelay = TRUE;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&noDelay, sizeof(noDelay));

                freeaddrinfo(result);
                return s;
            }

            closesocket(s);
        }

        freeaddrinfo(result);
        throw AdbError("cannot connect to " + host + ":" + portStr + ": " + lastError);
    }

    SOCKET listenLoopback(int& port)
    {
        ensureWinsock();

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET)
            throw AdbError("socket() failed: " + socketErrorText(WSAGetLastError()));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR || listen(s, SOMAXCONN) == SOCKET_ERROR)
        {
            int err = WSAGetLastError();
            closesocket(s);
            throw AdbError("cannot listen on 127.0.0.1:" + std::to_string(port) + ": " + socketErrorText(err));
        }

        int len = sizeof(addr);
        getsockname(s, (sockaddr*)&addr, &len);
        port = ntohs(addr.sin_port);
        return s;
    }

    void sendAll(SOCKET s, const void* data, size_t size)
    {
        const char* p = static_cast<const char*>(data);
        while (size > 0)
        {
            int chunk = (int)std::min<size_t>(size, 1 << 30);
            int sent = ::send(s, p, chunk, 0);
            if (sent <= 0)
                throw AdbError("send() failed: " + socketErrorText(WSAGetLastError()));

            p += sent;
            size -= sent;
        }
    }

    // ------------------------------------------------------------------------
    // TcpTransport
    // ------------------------------------------------------------------------
    TcpTransport::TcpTransport(const std::string& host, int port, std::chrono::milliseconds timeout)
    {
        sock = connectTcp(host, port, timeout);
    }

    TcpTransport::~TcpTransport()
    {
        if (sock != INVALID_SOCKET)
            closesocket(sock);
    }

    void TcpTransport::writeAll(const void* data, size_t size)
    {
        sendAll(sock, data, size);
    }

    void TcpTransport::readExact(void* data, size_t size)
    {
        char* p = static_cast<char*>(data);
        while (size > 0)
        {
            int chunk = (int)std::min<size_t>(size, 1 << 30);
            int r = recv(sock, p, chunk, 0);
            if (r == 0)
                throw AdbError("device closed the connection");
            if (r < 0)
                throw AdbError("recv() failed: " + socketErrorText(WSAGetLastError()));

            p += r;
            size -= r;
        }
    }

    bool TcpTransport::waitReadable(std::chrono::milliseconds timeout)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(sock, &readSet);

        timeval tv;
        tv.tv_sec = (long)(timeout.count() / 1000);
        tv.tv_usec = (long)(timeout.count() % 1000) * 1000;

        return select(0, &readSet, nullptr, nullptr, &tv) > 0;
    }

    void TcpTransport::shutdown()
    {
        ::shutdown(sock, SD_BOTH);
    }
}
