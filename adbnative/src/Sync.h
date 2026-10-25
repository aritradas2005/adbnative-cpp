// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include "Connection.h"

#include <filesystem>
#include <string>
#include <vector>

namespace adb::detail
{
    // ========================================================================
    //  One "sync:" session (system/core/adb/file_sync_protocol.h).
    //  A FAIL from the device ends the session, so errors throw.
    // ========================================================================
    class SyncSession
    {
    public:
        explicit SyncSession(Connection& conn);
        ~SyncSession();

        SyncSession(const SyncSession&) = delete;
        SyncSession& operator=(const SyncSession&) = delete;

        // false if the path does not exist. follow=false -> lstat.
        bool stat(const std::string& path, FileStat& out, bool follow = true);

        std::vector<DirEntry> list(const std::string& path);

        // Progress: done is advanced by the bytes sent/received.
        void sendFile(const std::filesystem::path& local, const std::string& remote, uint32_t mode,
                      const ProgressCallback& progress, uint64_t& done, uint64_t total);
        void sendData(const std::string& data, const std::string& remote, uint32_t mode, int64_t mtime);

        void recvFile(const std::string& remote, const std::filesystem::path& local,
                      const ProgressCallback& progress, uint64_t& done, uint64_t total);
        std::string recvData(const std::string& remote);

    private:
        void request(const char* id, const std::string& path);
        [[noreturn]] void throwFail(const std::string& context);

        // Collects DATA packets and writes them in max-payload sized batches.
        void queue(const std::string& packet);
        void flush();

        // Reads DATA/DONE/FAIL after RECV; calls sink for each chunk.
        template <typename Sink>
        void receive(const std::string& remote, Sink&& sink);

        void finishSend(const std::string& remote, int64_t mtime);

        Stream stream;
        bool statV2 = false;
        bool lsV2 = false;
        std::string pending;
    };
}
