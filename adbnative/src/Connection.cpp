// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "Connection.h"
#include "AdbKey.h"
#include "adb/Error.h"

#include <algorithm>
#include <cstdio>
#include <sstream>

namespace adb::detail
{
    namespace
    {
        // What we tell adbd we understand. Only features this library implements.
        const char* kHostFeatures =
            "shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,abb,abb_exec,"
            "fixed_push_symlink_timestamp,remount_shell";

        constexpr uint32_t kMaxIncomingPayload = 16 * 1024 * 1024;

        // ADBNATIVE_TRACE=1 prints every packet to stderr.
        bool traceEnabled()
        {
            static bool on = []
            {
                char buf[8];
                return GetEnvironmentVariableA("ADBNATIVE_TRACE", buf, sizeof(buf)) > 0 && buf[0] != '0';
            }();
            return on;
        }

        void trace(const char* dir, const Message& m)
        {
            std::string preview;
            for (size_t i = 0; i < m.data.size() && i < 48; i++)
            {
                unsigned char c = m.data[i];
                preview += (c >= 32 && c < 127) ? (char)c : '.';
            }
            fprintf(stderr, "[adb] %s %s %u %u len=%zu \"%s\"\n", dir, commandName(m.command).c_str(),
                    m.arg0, m.arg1, m.data.size(), preview.c_str());
        }
    }

    // =========================================================================
    // CONNECT + HANDSHAKE
    // =========================================================================
    std::shared_ptr<Connection> Connection::create(const std::string& host, int port,
                                                   const ConnectOptions& options)
    {
        std::shared_ptr<Connection> conn(new Connection(host, port, options));

        auto key = AdbKey::loadOrCreate(options.keyPath.empty() ? AdbKey::defaultPath() : options.keyPath);
        conn->handshake(*key);

        conn->reader = std::thread([raw = conn.get()] { raw->readerLoop(); });
        return conn;
    }

    Connection::Connection(const std::string& host, int port, const ConnectOptions& options)
        : options(options)
    {
        transport = std::make_unique<TcpTransport>(host, port, options.connectTimeout);
        deviceInfo.host = host;
        deviceInfo.port = port;
    }

    Connection::~Connection()
    {
        close();
        if (reader.joinable())
        {
            // The last reference can be dropped on the reader thread itself
            // (an incoming-stream handler finishing there).
            if (reader.get_id() == std::this_thread::get_id())
            {
                *readerDestroyedFlag = true;
                reader.detach();
            }
            else
                reader.join();
        }
    }

    void Connection::handshake(AdbKey& key)
    {
        send(A_CNXN, A_VERSION, MAX_PAYLOAD, std::string("host::features=") + kHostFeatures);

        auto deadline = std::chrono::steady_clock::now() + options.authTimeout;
        bool signedToken = false;
        bool sentPublicKey = false;

        while (true)
        {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());

            if (remaining.count() <= 0 || !transport->waitReadable(remaining))
            {
                if (sentPublicKey)
                    throw AdbError("device unauthorized: accept the \"Allow USB debugging\" prompt on the device");
                throw AdbError("timed out waiting for the device to answer CNXN");
            }

            Message m;
            readMessage(m);

            if (m.command == A_CNXN)
            {
                deviceInfo.protocolVersion = m.arg0;
                deviceInfo.maxPayload = std::min<uint32_t>(m.arg1, MAX_PAYLOAD);
                if (deviceInfo.maxPayload == 0)
                    deviceInfo.maxPayload = 4096;
                parseBanner(m.data);
                return;
            }

            if (m.command == A_AUTH && m.arg0 == AUTH_TOKEN)
            {
                // First token: prove we own a key it already trusts.
                // Second token: it didn't -> offer our public key (device shows the prompt).
                if (!signedToken)
                {
                    send(A_AUTH, AUTH_SIGNATURE, 0, key.sign(m.data));
                    signedToken = true;
                }
                else if (!sentPublicKey)
                {
                    send(A_AUTH, AUTH_RSAPUBLICKEY, 0, key.androidPublicKey() + '\0');
                    sentPublicKey = true;
                }
                continue;
            }

            if (m.command == A_STLS)
                throw AdbError("device requires TLS (Android 11+ wireless debugging), which is not supported");

            // anything else before CNXN is ignored
        }
    }

    void Connection::parseBanner(const std::string& banner)
    {
        // "device::ro.product.name=x;ro.product.model=y;ro.product.device=z;features=a,b,c"
        std::string text = banner;
        while (!text.empty() && text.back() == '\0')
            text.pop_back();

        deviceInfo.banner = text;

        size_t props = text.find("::");
        if (props == std::string::npos)
            return;

        std::stringstream ss(text.substr(props + 2));
        std::string item;
        while (std::getline(ss, item, ';'))
        {
            size_t eq = item.find('=');
            if (eq == std::string::npos)
                continue;

            std::string k = item.substr(0, eq);
            std::string v = item.substr(eq + 1);

            if (k == "ro.product.name")
                deviceInfo.product = v;
            else if (k == "ro.product.model")
                deviceInfo.model = v;
            else if (k == "ro.product.device")
                deviceInfo.device = v;
            else if (k == "features")
            {
                std::stringstream fs(v);
                std::string f;
                while (std::getline(fs, f, ','))
                    if (!f.empty())
                        deviceInfo.features.push_back(f);
            }
        }
    }

    bool Connection::hasFeature(const std::string& feature) const
    {
        return std::find(deviceInfo.features.begin(), deviceInfo.features.end(), feature) != deviceInfo.features.end();
    }

    // =========================================================================
    // PACKET IO
    // =========================================================================
    void Connection::readMessage(Message& m)
    {
        uint8_t header[HEADER_SIZE];
        transport->readExact(header, HEADER_SIZE);

        uint32_t length = 0;
        if (!decodeHeader(header, m, length))
            throw AdbError("corrupt packet from device (bad magic)");
        if (length > kMaxIncomingPayload)
            throw AdbError("corrupt packet from device (payload too large)");

        m.data.resize(length);
        if (length)
            transport->readExact(m.data.data(), length);

        if (traceEnabled())
            trace("<<", m);
    }

    void Connection::send(uint32_t command, uint32_t arg0, uint32_t arg1, std::string data)
    {
        if (dead)
            throw AdbError("connection to device lost");

        Message m{ command, arg0, arg1, std::move(data) };
        if (traceEnabled())
            trace(">>", m);
        std::string packet = encodeMessage(m);

        std::lock_guard<std::mutex> lock(writeMutex);
        try
        {
            transport->writeAll(packet.data(), packet.size());
        }
        catch (...)
        {
            transport->shutdown();      // let the reader notice and clean up
            throw;
        }
    }

    // =========================================================================
    // READER THREAD
    // =========================================================================
    void Connection::readerLoop()
    {
        bool destroyed = false;
        readerDestroyedFlag = &destroyed;

        try
        {
            while (!dead)
            {
                Message m;
                readMessage(m);
                dispatch(m);
                if (destroyed)
                    return;              // 'this' is gone
            }
        }
        catch (...)
        {
            if (destroyed)
                return;
        }

        markDead();
    }

    std::shared_ptr<StreamState> Connection::findStream(uint32_t localId)
    {
        std::lock_guard<std::mutex> lock(streamsMutex);
        auto it = streams.find(localId);
        return it == streams.end() ? nullptr : it->second;
    }

    void Connection::dispatch(Message& m)
    {
        switch (m.command)
        {
        case A_OKAY:
        {
            auto st = findStream(m.arg1);
            if (!st)
                return;

            std::lock_guard<std::mutex> lock(st->mutex);
            if (st->phase == StreamState::Phase::Opening)
            {
                st->remoteId = m.arg0;
                st->phase = StreamState::Phase::Open;
                st->accepted = true;
                st->writeReady = true;
            }
            else if (st->phase == StreamState::Phase::Open && st->remoteId == m.arg0)
            {
                st->writeReady = true;
            }
            st->cv.notify_all();
            return;
        }

        case A_WRTE:
        {
            auto st = findStream(m.arg1);
            if (!st)
                return;

            bool ackNow = false;
            {
                std::lock_guard<std::mutex> lock(st->mutex);
                if (st->phase != StreamState::Phase::Open)
                    return;

                // Acked when the reader consumes it (Connection::read), which is
                // what gives us back-pressure. Empty packets are acked right away.
                if (m.data.empty())
                    ackNow = true;
                else
                    st->rx.push_back(std::move(m.data));
                st->cv.notify_all();
            }

            if (ackNow)
                send(A_OKAY, st->localId, st->remoteId);
            return;
        }

        case A_CLSE:
        {
            auto st = findStream(m.arg1);
            if (!st)
                return;

            {
                std::lock_guard<std::mutex> lock(st->mutex);
                st->phase = StreamState::Phase::Closed;
                st->cv.notify_all();
            }

            std::lock_guard<std::mutex> lock(streamsMutex);
            streams.erase(m.arg1);
            return;
        }

        case A_OPEN:
            handleIncomingOpen(m);
            return;

        default:
            // CNXN/AUTH after the handshake, unknown commands: ignore
            return;
        }
    }

    void Connection::handleIncomingOpen(Message& m)
    {
        std::string service = m.data;
        while (!service.empty() && service.back() == '\0')
            service.pop_back();

        IncomingHandler handler;
        {
            std::lock_guard<std::mutex> lock(handlerMutex);
            handler = incomingHandler;
        }

        if (!handler)
        {
            send(A_CLSE, 0, m.arg0);
            return;
        }

        auto st = std::make_shared<StreamState>();
        st->localId = nextLocalId++;
        st->remoteId = m.arg0;
        st->phase = StreamState::Phase::Open;
        st->accepted = true;
        st->writeReady = false;          // until we sent our OKAY

        {
            std::lock_guard<std::mutex> lock(streamsMutex);
            streams[st->localId] = st;
        }

        Stream stream(std::make_shared<StreamHandle>(shared_from_this(), st));

        bool accepted = false;
        try
        {
            accepted = handler(service, stream);
        }
        catch (...)
        {
        }

        if (!accepted)
            return;                      // ~Stream sends CLSE

        send(A_OKAY, st->localId, st->remoteId);

        std::lock_guard<std::mutex> lock(st->mutex);
        st->writeReady = true;
        st->cv.notify_all();
    }

    void Connection::markDead()
    {
        dead = true;

        std::map<uint32_t, std::shared_ptr<StreamState>> all;
        {
            std::lock_guard<std::mutex> lock(streamsMutex);
            all.swap(streams);
        }

        for (auto& [id, st] : all)
        {
            std::lock_guard<std::mutex> lock(st->mutex);
            st->phase = StreamState::Phase::Closed;
            st->cv.notify_all();
        }
    }

    void Connection::close()
    {
        if (closing.exchange(true))
            return;

        transport->shutdown();           // reader thread's recv fails -> markDead
        if (reader.joinable() && reader.get_id() != std::this_thread::get_id())
            reader.join();
        markDead();
    }

    void Connection::setIncomingHandler(IncomingHandler handler)
    {
        std::lock_guard<std::mutex> lock(handlerMutex);
        incomingHandler = std::move(handler);
    }

    // =========================================================================
    // STREAMS
    // =========================================================================
    Stream Connection::open(const std::string& service)
    {
        auto st = std::make_shared<StreamState>();
        st->localId = nextLocalId++;

        {
            std::lock_guard<std::mutex> lock(streamsMutex);
            streams[st->localId] = st;
        }

        auto forget = [&]
        {
            std::lock_guard<std::mutex> lock(streamsMutex);
            streams.erase(st->localId);
        };

        try
        {
            send(A_OPEN, st->localId, 0, service + '\0');
        }
        catch (...)
        {
            forget();
            throw;
        }

        std::unique_lock<std::mutex> lk(st->mutex);
        bool answered = st->cv.wait_for(lk, options.openTimeout,
                                        [&] { return st->phase != StreamState::Phase::Opening; });

        if (!answered)
        {
            st->phase = StreamState::Phase::Closed;
            lk.unlock();
            forget();
            throw AdbError("timed out opening service '" + service + "'");
        }

        if (!st->accepted)
        {
            lk.unlock();
            forget();
            if (dead)
                throw AdbError("connection to device lost");
            throw AdbError("device refused service '" + service + "'");
        }

        lk.unlock();
        return Stream(std::make_shared<StreamHandle>(shared_from_this(), st));
    }

    size_t Connection::read(StreamState& st, void* buffer, size_t size)
    {
        if (size == 0)
            return 0;

        std::unique_lock<std::mutex> lk(st.mutex);
        st.cv.wait(lk, [&] { return !st.rx.empty() || st.phase == StreamState::Phase::Closed; });

        if (st.rx.empty())
            return 0;

        std::string& front = st.rx.front();
        size_t n = std::min(size, front.size() - st.rxOffset);
        memcpy(buffer, front.data() + st.rxOffset, n);
        st.rxOffset += n;

        bool ack = false;
        if (st.rxOffset == front.size())
        {
            st.rx.pop_front();
            st.rxOffset = 0;
            ack = st.phase == StreamState::Phase::Open;
        }

        uint32_t localId = st.localId;
        uint32_t remoteId = st.remoteId;
        lk.unlock();

        if (ack)
        {
            try
            {
                send(A_OKAY, localId, remoteId);
            }
            catch (...)
            {
            }
        }

        return n;
    }

    void Connection::write(StreamState& st, const void* data, size_t size)
    {
        const char* p = static_cast<const char*>(data);
        size_t maxChunk = deviceInfo.maxPayload;

        while (size > 0)
        {
            std::unique_lock<std::mutex> lk(st.mutex);
            st.cv.wait(lk, [&] { return st.writeReady || st.phase == StreamState::Phase::Closed; });

            if (st.phase == StreamState::Phase::Closed)
                throw AdbError(dead ? "connection to device lost" : "stream closed by device");

            st.writeReady = false;
            uint32_t localId = st.localId;
            uint32_t remoteId = st.remoteId;
            lk.unlock();

            size_t chunk = std::min(size, maxChunk);
            send(A_WRTE, localId, remoteId, std::string(p, chunk));
            p += chunk;
            size -= chunk;
        }
    }

    void Connection::closeStream(StreamState& st)
    {
        bool sendClose = false;
        {
            std::lock_guard<std::mutex> lock(st.mutex);
            sendClose = st.phase == StreamState::Phase::Open;
            st.phase = StreamState::Phase::Closed;
            st.rx.clear();
            st.cv.notify_all();
        }

        {
            std::lock_guard<std::mutex> lock(streamsMutex);
            streams.erase(st.localId);
        }

        if (sendClose && !dead)
        {
            try
            {
                send(A_CLSE, st.localId, st.remoteId);
            }
            catch (...)
            {
            }
        }
    }
}
