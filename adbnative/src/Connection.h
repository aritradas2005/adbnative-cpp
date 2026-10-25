// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include "Net.h"
#include "Protocol.h"
#include "adb/Stream.h"
#include "adb/Types.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace adb::detail
{
    class AdbKey;

    // State of one stream, shared between the reader thread and Stream handles.
    struct StreamState
    {
        enum class Phase { Opening, Open, Closed };

        uint32_t localId = 0;
        uint32_t remoteId = 0;
        Phase phase = Phase::Opening;
        bool accepted = false;           // device answered OPEN with OKAY at some point

        std::deque<std::string> rx;      // received WRTE payloads not yet read
        size_t rxOffset = 0;             // bytes of rx.front() already consumed
        bool writeReady = false;         // peer acked our last WRTE

        std::mutex mutex;
        std::condition_variable cv;
    };

    // ========================================================================
    //  One adbd connection: handshake + auth, then a reader thread that
    //  demultiplexes packets into streams.
    // ========================================================================
    class Connection : public std::enable_shared_from_this<Connection>
    {
    public:
        // Called on the reader thread when the device opens a stream to us (adb reverse).
        // Return false to refuse it.
        using IncomingHandler = std::function<bool(const std::string& service, Stream stream)>;

        static std::shared_ptr<Connection> create(const std::string& host, int port,
                                                  const ConnectOptions& options);
        ~Connection();

        const DeviceInfo& info() const { return deviceInfo; }
        bool hasFeature(const std::string& feature) const;
        bool alive() const { return !dead; }

        // OPEN service -> waits for OKAY. Throws AdbError if refused.
        Stream open(const std::string& service);

        void setIncomingHandler(IncomingHandler handler);

        // Used by Stream
        size_t read(StreamState& st, void* buffer, size_t size);
        void write(StreamState& st, const void* data, size_t size);
        void closeStream(StreamState& st);

        // Tears down the transport and closes every stream.
        void close();

    private:
        Connection(const std::string& host, int port, const ConnectOptions& options);

        void handshake(AdbKey& key);
        void parseBanner(const std::string& banner);
        void readMessage(Message& m);
        void send(uint32_t command, uint32_t arg0, uint32_t arg1, std::string data = {});

        void readerLoop();
        void dispatch(Message& m);
        void handleIncomingOpen(Message& m);
        std::shared_ptr<StreamState> findStream(uint32_t localId);
        void markDead();

        ConnectOptions options;
        DeviceInfo deviceInfo;
        std::unique_ptr<TcpTransport> transport;

        std::mutex writeMutex;
        std::mutex streamsMutex;
        std::map<uint32_t, std::shared_ptr<StreamState>> streams;
        std::atomic<uint32_t> nextLocalId{ 1 };

        std::mutex handlerMutex;
        IncomingHandler incomingHandler;

        std::atomic<bool> dead{ false };
        std::atomic<bool> closing{ false };
        std::thread reader;
        bool* readerDestroyedFlag = nullptr;   // set when ~Connection runs on the reader thread
    };

    // What Stream points at. Closing the last handle closes the stream.
    struct StreamHandle
    {
        std::shared_ptr<Connection> conn;
        std::shared_ptr<StreamState> state;

        StreamHandle(std::shared_ptr<Connection> c, std::shared_ptr<StreamState> s)
            : conn(std::move(c)), state(std::move(s))
        {
        }

        ~StreamHandle()
        {
            conn->closeStream(*state);
        }
    };
}
