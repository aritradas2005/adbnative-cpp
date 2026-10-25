// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "Sync.h"
#include "DeviceCore.h"
#include "Util.h"
#include "adb/Device.h"

#include <algorithm>
#include <ctime>
#include <fstream>

namespace adb
{
    using namespace detail;

    namespace
    {
        constexpr size_t kSyncDataMax = 64 * 1024;   // SYNC_DATA_MAX
        constexpr size_t kMaxPathLength = 1024;

        int64_t unixTime(const std::filesystem::file_time_type& t)
        {
            auto sys = std::chrono::clock_cast<std::chrono::system_clock>(t);
            return std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count();
        }

        std::string remoteBasename(std::string path)
        {
            while (path.size() > 1 && path.back() == '/')
                path.pop_back();
            size_t slash = path.rfind('/');
            return slash == std::string::npos ? path : path.substr(slash + 1);
        }

        std::string remoteJoin(const std::string& dir, const std::string& name)
        {
            if (dir.empty() || dir.back() == '/')
                return dir + name;
            return dir + "/" + name;
        }
    }

    // =========================================================================
    // SYNC SESSION
    // =========================================================================
    namespace detail
    {
        SyncSession::SyncSession(Connection& conn)
            : stream(conn.open("sync:")),
              statV2(conn.hasFeature("stat_v2")),
              lsV2(conn.hasFeature("ls_v2"))
        {
        }

        SyncSession::~SyncSession()
        {
            try
            {
                std::string quit = "QUIT";
                putU32(quit, 0);
                stream.write(quit);
            }
            catch (...)
            {
            }
        }

        void SyncSession::request(const char* id, const std::string& path)
        {
            if (path.size() > kMaxPathLength)
                throw AdbError("remote path too long: " + path);

            std::string packet(id, 4);
            putU32(packet, (uint32_t)path.size());
            packet += path;
            stream.write(packet);
        }

        void SyncSession::throwFail(const std::string& context)
        {
            // "FAIL" already consumed; then u32 length + message
            uint8_t len[4];
            stream.readExact(len, 4);
            std::string message(getU32(len), '\0');
            if (!message.empty())
                stream.readExact(message.data(), message.size());
            throw AdbError(context + ": " + message);
        }

        bool SyncSession::stat(const std::string& path, FileStat& out, bool follow)
        {
            if (statV2)
            {
                const char* id = follow ? "STA2" : "LST2";
                request(id, path);

                uint8_t reply[4 + 68];
                stream.readExact(reply, sizeof(reply));
                if (memcmp(reply, id, 4) != 0)
                    throw AdbError("sync: unexpected reply to " + std::string(id));

                const uint8_t* p = reply + 4;
                uint32_t error = getU32(p);
                if (error != 0)
                    return false;

                out.mode = getU32(p + 20);
                out.size = getU64(p + 36);
                out.mtime = (int64_t)getU64(p + 52);
                return true;
            }

            // v1 is always lstat
            request("STAT", path);
            uint8_t reply[16];
            stream.readExact(reply, sizeof(reply));
            if (memcmp(reply, "STAT", 4) != 0)
                throw AdbError("sync: unexpected reply to STAT");

            out.mode = getU32(reply + 4);
            out.size = getU32(reply + 8);
            out.mtime = getU32(reply + 12);
            return out.mode != 0;
        }

        std::vector<DirEntry> SyncSession::list(const std::string& path)
        {
            std::vector<DirEntry> entries;

            request(lsV2 ? "LIS2" : "LIST", path);

            while (true)
            {
                char id[4];
                stream.readExact(id, 4);

                DirEntry e;
                uint32_t nameLength = 0;

                if (lsV2)
                {
                    uint8_t d[72];
                    stream.readExact(d, sizeof(d));
                    if (memcmp(id, "DONE", 4) == 0)
                        break;
                    if (memcmp(id, "DNT2", 4) != 0)
                        throw AdbError("sync: unexpected reply to LIS2");

                    e.stat.mode = getU32(d + 20);
                    e.stat.size = getU64(d + 36);
                    e.stat.mtime = (int64_t)getU64(d + 52);
                    nameLength = getU32(d + 68);
                }
                else
                {
                    uint8_t d[16];
                    stream.readExact(d, sizeof(d));
                    if (memcmp(id, "DONE", 4) == 0)
                        break;
                    if (memcmp(id, "DENT", 4) != 0)
                        throw AdbError("sync: unexpected reply to LIST");

                    e.stat.mode = getU32(d);
                    e.stat.size = getU32(d + 4);
                    e.stat.mtime = getU32(d + 8);
                    nameLength = getU32(d + 12);
                }

                e.name.resize(nameLength);
                if (nameLength)
                    stream.readExact(e.name.data(), nameLength);

                if (e.name != "." && e.name != "..")
                    entries.push_back(std::move(e));
            }

            return entries;
        }

        // ---------------------------------------------------------------------
        // SEND
        // ---------------------------------------------------------------------
        void SyncSession::queue(const std::string& packet)
        {
            if (!pending.empty() && pending.size() + packet.size() > stream.maxPayload())
                flush();
            pending += packet;
        }

        void SyncSession::flush()
        {
            if (!pending.empty())
            {
                stream.write(pending);
                pending.clear();
            }
        }

        void SyncSession::finishSend(const std::string& remote, int64_t mtime)
        {
            std::string done = "DONE";
            putU32(done, (uint32_t)mtime);
            queue(done);
            flush();

            char id[4];
            stream.readExact(id, 4);
            if (memcmp(id, "FAIL", 4) == 0)
                throwFail("push " + remote + " failed");
            if (memcmp(id, "OKAY", 4) != 0)
                throw AdbError("sync: unexpected reply to DONE");

            uint8_t zero[4];
            stream.readExact(zero, 4);
        }

        void SyncSession::sendFile(const std::filesystem::path& local, const std::string& remote, uint32_t mode,
                                   const ProgressCallback& progress, uint64_t& done, uint64_t total)
        {
            std::ifstream file(local, std::ios::binary);
            if (!file)
                throw AdbError("cannot open local file " + fromPath(local));

            // "<path>,<mode>" with mode in decimal including S_IFREG, as adb sends it
            request("SEND", remote + "," + std::to_string(0100000 | (mode & 07777)));

            std::string buffer(kSyncDataMax, '\0');
            while (true)
            {
                file.read(buffer.data(), buffer.size());
                std::streamsize n = file.gcount();
                if (n <= 0)
                    break;

                std::string packet = "DATA";
                putU32(packet, (uint32_t)n);
                packet.append(buffer.data(), (size_t)n);
                queue(packet);

                done += n;
                if (progress)
                    progress(remote, done, total);
            }

            std::error_code ec;
            auto mtime = std::filesystem::last_write_time(local, ec);
            finishSend(remote, ec ? (int64_t)std::time(nullptr) : unixTime(mtime));
        }

        void SyncSession::sendData(const std::string& data, const std::string& remote, uint32_t mode, int64_t mtime)
        {
            request("SEND", remote + "," + std::to_string(0100000 | (mode & 07777)));

            for (size_t off = 0; off < data.size(); off += kSyncDataMax)
            {
                size_t n = std::min(kSyncDataMax, data.size() - off);
                std::string packet = "DATA";
                putU32(packet, (uint32_t)n);
                packet.append(data, off, n);
                queue(packet);
            }

            finishSend(remote, mtime);
        }

        // ---------------------------------------------------------------------
        // RECV
        // ---------------------------------------------------------------------
        template <typename Sink>
        void SyncSession::receive(const std::string& remote, Sink&& sink)
        {
            request("RECV", remote);

            std::string buffer;
            while (true)
            {
                char id[4];
                stream.readExact(id, 4);

                if (memcmp(id, "FAIL", 4) == 0)
                    throwFail("pull " + remote + " failed");

                uint8_t len[4];
                stream.readExact(len, 4);

                if (memcmp(id, "DONE", 4) == 0)
                    break;
                if (memcmp(id, "DATA", 4) != 0)
                    throw AdbError("sync: unexpected reply to RECV");

                buffer.resize(getU32(len));
                stream.readExact(buffer.data(), buffer.size());
                sink(buffer);
            }
        }

        void SyncSession::recvFile(const std::string& remote, const std::filesystem::path& local,
                                   const ProgressCallback& progress, uint64_t& done, uint64_t total)
        {
            std::filesystem::path tmp = local;
            tmp += ".adbpart";

            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out)
                throw AdbError("cannot write local file " + fromPath(local));

            try
            {
                receive(remote, [&](const std::string& chunk)
                {
                    out.write(chunk.data(), chunk.size());
                    done += chunk.size();
                    if (progress)
                        progress(remote, done, total);
                });
            }
            catch (...)
            {
                out.close();
                std::error_code ec;
                std::filesystem::remove(tmp, ec);
                throw;
            }

            out.close();
            if (!out)
                throw AdbError("error writing local file " + fromPath(local));

            std::filesystem::rename(tmp, local);
        }

        std::string SyncSession::recvData(const std::string& remote)
        {
            std::string data;
            receive(remote, [&](const std::string& chunk) { data += chunk; });
            return data;
        }
    }

    // =========================================================================
    // DEVICE FILE API
    // =========================================================================
    bool Device::exists(const std::string& remotePath)
    {
        FileStat st;
        SyncSession sync(*core->connection());
        return sync.stat(remotePath, st, false);
    }

    FileStat Device::stat(const std::string& remotePath)
    {
        FileStat st;
        SyncSession sync(*core->connection());
        if (!sync.stat(remotePath, st, true))
            throw AdbError("remote object '" + remotePath + "' does not exist");
        return st;
    }

    std::vector<DirEntry> Device::list(const std::string& remoteDir)
    {
        SyncSession sync(*core->connection());
        return sync.list(remoteDir);
    }

    void Device::push(const std::string& localPath, const std::string& remotePath, const ProgressCallback& progress)
    {
        namespace fs = std::filesystem;

        fs::path local = toPath(localPath);
        if (!fs::exists(local))
            throw AdbError("local path does not exist: " + localPath);
        if (!local.has_filename())
            local = local.parent_path();     // "C:\dir\" -> "C:\dir"

        auto conn = core->connection();
        SyncSession sync(*conn);

        FileStat remoteStat;
        bool remoteIsDir = sync.stat(remotePath, remoteStat, true) && remoteStat.isDirectory();
        std::string target = remoteIsDir ? remoteJoin(remotePath, fromPath(local.filename())) : remotePath;

        if (!fs::is_directory(local))
        {
            uint64_t done = 0;
            sync.sendFile(local, target, 0644, progress, done, fs::file_size(local));
            return;
        }

        // Directory: send every file; adbd creates parent directories itself
        // (fixed_push_mkdir), empty ones are made with mkdir -p afterwards.
        struct Item { fs::path local; std::string remote; };
        std::vector<Item> files;
        std::vector<std::string> emptyDirs;
        uint64_t total = 0;

        if (fs::is_empty(local))
            emptyDirs.push_back(target);

        for (auto& entry : fs::recursive_directory_iterator(local))
        {
            std::u8string generic = fs::relative(entry.path(), local).generic_u8string();
            std::string remote = remoteJoin(target, std::string(generic.begin(), generic.end()));

            if (entry.is_directory())
            {
                if (fs::is_empty(entry.path()))
                    emptyDirs.push_back(remote);
            }
            else if (entry.is_regular_file())
            {
                files.push_back({ entry.path(), remote });
                total += entry.file_size();
            }
        }

        uint64_t done = 0;
        for (auto& f : files)
            sync.sendFile(f.local, f.remote, 0644, progress, done, total);

        if (!emptyDirs.empty())
        {
            std::string cmd = "mkdir -p";
            for (auto& d : emptyDirs)
                cmd += " " + shellQuote(d);

            ShellResult r = shell(cmd);
            if (r.exitCode > 0)
                throw AdbError("mkdir failed: " + trimRight(r.err + r.out));
        }
    }

    void Device::pull(const std::string& remotePath, const std::string& localPath, const ProgressCallback& progress)
    {
        namespace fs = std::filesystem;

        auto conn = core->connection();
        SyncSession sync(*conn);

        FileStat st;
        if (!sync.stat(remotePath, st, true))
            throw AdbError("remote object '" + remotePath + "' does not exist");

        fs::path local = toPath(localPath);
        fs::path dest = fs::is_directory(local) ? local / toPath(remoteBasename(remotePath)) : local;

        if (!st.isDirectory())
        {
            uint64_t done = 0;
            sync.recvFile(remotePath, dest, progress, done, st.size);
            return;
        }

        struct Item { std::string remote; fs::path local; };
        std::vector<Item> files;
        std::vector<fs::path> dirs{ dest };
        uint64_t total = 0;

        // Walk the tree first so progress has a total.
        std::vector<std::pair<std::string, fs::path>> pendingDirs{ { remotePath, dest } };
        while (!pendingDirs.empty())
        {
            auto [rdir, ldir] = pendingDirs.back();
            pendingDirs.pop_back();

            for (auto& e : sync.list(rdir))
            {
                std::string r = remoteJoin(rdir, e.name);
                fs::path l = ldir / toPath(e.name);
                FileStat s = e.stat;

                if (s.isSymlink())
                {
                    // follow links to files; skip links to directories (cycles)
                    if (!sync.stat(r, s, true) || s.isDirectory())
                        continue;
                }

                if (s.isDirectory())
                {
                    dirs.push_back(l);
                    pendingDirs.push_back({ r, l });
                }
                else if (s.isRegular())
                {
                    files.push_back({ r, l });
                    total += s.size;
                }
            }
        }

        for (auto& d : dirs)
            fs::create_directories(d);

        uint64_t done = 0;
        for (auto& f : files)
            sync.recvFile(f.remote, f.local, progress, done, total);
    }

    void Device::pushData(const std::string& data, const std::string& remotePath, uint32_t mode)
    {
        SyncSession sync(*core->connection());
        sync.sendData(data, remotePath, mode, (int64_t)std::time(nullptr));
    }

    std::string Device::pullData(const std::string& remotePath)
    {
        SyncSession sync(*core->connection());
        return sync.recvData(remotePath);
    }
}
