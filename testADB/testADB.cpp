// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

// ============================================================================
//   adbnative test runner — exercises the library against a live emulator.
//   Usage: testADB [serial]     e.g. testADB 127.0.0.1:7555
//   Without a serial it scans the usual emulator ports and uses the first hit.
// ============================================================================

#include <adb/adb.h>
#include "../adbnative/src/AdbKey.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

static int passed = 0;
static int failed = 0;
static int skipped = 0;

struct Skip
{
    std::string why;
};

#define CHECK(cond, msg)                                     \
    do                                                       \
    {                                                        \
        if (!(cond))                                         \
            throw std::runtime_error(std::string(msg));      \
    } while (0)

template <typename F>
void test(const char* name, F&& body)
{
    auto t0 = Clock::now();
    try
    {
        std::string detail = body();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
        passed++;
        std::cout << "[PASS] " << name << " (" << ms << " ms)" << (detail.empty() ? "" : "  " + detail) << "\n";
    }
    catch (const Skip& s)
    {
        skipped++;
        std::cout << "[SKIP] " << name << ": " << s.why << "\n";
    }
    catch (const std::exception& e)
    {
        failed++;
        std::cout << "[FAIL] " << name << ": " << e.what() << "\n";
    }
}

static std::string randomBytes(size_t n, unsigned seed)
{
    std::mt19937 rng(seed);
    std::string s(n, '\0');
    for (auto& c : s)
        c = (char)(rng() & 0xFF);
    return s;
}

static void writeFile(const fs::path& p, const std::string& data)
{
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << data;
}

static std::string readFile(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string mbps(uint64_t bytes, Clock::duration d)
{
    double s = std::chrono::duration<double>(d).count();
    std::ostringstream o;
    o.precision(1);
    o << std::fixed << (bytes / 1048576.0) / (s > 0 ? s : 1e-9) << " MB/s";
    return o.str();
}

// Blocking read of everything from a local socket until the peer closes.
static std::string recvAll(SOCKET s)
{
    std::string out;
    char buf[4096];
    while (true)
    {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0)
            break;
        out.append(buf, r);
    }
    return out;
}

int main(int argc, char** argv)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    fs::path tmp = fs::temp_directory_path() / "adbnative_test";
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    const std::string R = "/data/local/tmp/adbnative_test";

    // ------------------------------------------------------------------------
    // KEY (pure local, no device)
    // ------------------------------------------------------------------------
    test("adbkey: computed public key matches adbkey.pub", []
    {
        auto key = adb::detail::AdbKey::loadOrCreate(adb::detail::AdbKey::defaultPath());
        std::string fromFile = key->androidPublicKey();
        std::string computed = key->computedPublicKey();
        std::string a = fromFile.substr(0, fromFile.find(' '));
        std::string b = computed.substr(0, computed.find(' '));
        CHECK(a == b, "android pubkey encoding differs from Google's adbkey.pub");
        std::string sig = key->sign(std::string(20, 'x'));
        CHECK(sig.size() == 256, "signature size " + std::to_string(sig.size()));
        return std::string("pubkey ") + std::to_string(a.size()) + " b64 chars, signature 256 bytes";
    });

    test("adbkey: generate, save, reload", [&]
    {
        fs::path p1 = tmp / "key1" / "adbkey";
        fs::path p2 = tmp / "key2" / "adbkey";
        auto k1 = adb::detail::AdbKey::loadOrCreate(p1.string());
        CHECK(fs::exists(p1) && fs::exists(p1.string() + ".pub"), "key files not written");
        CHECK(readFile(p1).rfind("-----BEGIN PRIVATE KEY-----", 0) == 0, "not a PKCS#8 PEM");

        fs::create_directories(p2.parent_path());
        fs::copy_file(p1, p2);                       // no .pub -> must re-derive it
        auto k2 = adb::detail::AdbKey::loadOrCreate(p2.string());
        CHECK(k1->computedPublicKey() == k2->computedPublicKey(), "reloaded key differs");
        return std::string();
    });

    // ------------------------------------------------------------------------
    // CONNECT
    // ------------------------------------------------------------------------
    adb::Device dev;

    test("discovery: findEmulators", [&]
    {
        auto t0 = Clock::now();
        auto found = adb::findEmulators();
        std::ostringstream o;
        o << found.size() << " found in "
          << std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count() << " ms:";
        for (auto& d : found)
            o << " " << d.serial() << "(" << d.info().model << ")";

        if (argc < 2)
        {
            CHECK(!found.empty(), "no emulator answered");
            dev = found.front();
        }
        return o.str();
    });

    if (argc >= 2)
    {
        test("connect", [&]
        {
            dev = adb::Device::connect(argv[1]);
            return dev.serial();
        });
    }

    if (!dev.valid())
    {
        std::cout << "\nNo device - stopping.\n";
        return 1;
    }

    test("device info (CNXN banner)", [&]
    {
        auto& i = dev.info();
        CHECK(!i.features.empty(), "no features in banner");
        std::ostringstream o;
        o << i.serial << " model=" << i.model << " product=" << i.product << " maxPayload=" << i.maxPayload
          << " version=0x" << std::hex << i.protocolVersion << std::dec << " features=" << i.features.size()
          << " shell_v2=" << dev.hasFeature("shell_v2") << " abb_exec=" << dev.hasFeature("abb_exec");
        return o.str();
    });

    // ------------------------------------------------------------------------
    // SHELL
    // ------------------------------------------------------------------------
    test("shell: stdout", [&]
    {
        auto r = dev.shell("echo hello");
        CHECK(r.out == "hello\n", "got '" + r.out + "'");
        return std::string();
    });

    test("shell: exit code + stderr", [&]
    {
        if (!dev.hasFeature("shell_v2"))
            throw Skip{ "device has no shell_v2" };
        auto r = dev.shell("echo out; echo err >&2; exit 3");
        CHECK(r.exitCode == 3, "exit code " + std::to_string(r.exitCode));
        CHECK(r.out == "out\n", "stdout '" + r.out + "'");
        CHECK(r.err == "err\n", "stderr '" + r.err + "'");
        return std::string();
    });

    test("shell: command reading stdin does not hang", [&]
    {
        auto r = dev.shell("cat");
        CHECK(r.exitCode == 0 || r.exitCode == -1, "exit " + std::to_string(r.exitCode));
        return std::string();
    });

    test("shell: large output (2 MB)", [&]
    {
        auto t0 = Clock::now();
        auto r = dev.shell("head -c 2097152 /dev/zero | tr '\\0' 'a'");
        CHECK(r.out.size() == 2097152, "got " + std::to_string(r.out.size()) + " bytes");
        CHECK(r.out.find_first_not_of('a') == std::string::npos, "corrupted output");
        return mbps(r.out.size(), Clock::now() - t0);
    });

    test("shellStream: stop early", [&]
    {
        size_t got = 0;
        int code = dev.shellStream("yes", [&](std::string_view d) { got += d.size(); return got < 200000; });
        CHECK(code == -1, "expected -1");
        CHECK(dev.shell("echo still-alive").out == "still-alive\n", "connection broken after cancel");
        return std::to_string(got) + " bytes before stop";
    });

    test("shell: 8 parallel commands", [&]
    {
        std::atomic<int> ok{ 0 };
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; i++)
        {
            threads.emplace_back([&, i]
            {
                try
                {
                    if (dev.shell("echo " + std::to_string(i)).out == std::to_string(i) + "\n")
                        ok++;
                }
                catch (...)
                {
                }
            });
        }
        for (auto& t : threads)
            t.join();
        CHECK(ok == 8, std::to_string(ok.load()) + "/8 succeeded");
        return std::string();
    });

    test("getprop / getProps", [&]
    {
        std::string sdk = dev.getProp("ro.build.version.sdk");
        std::string rel = dev.getProp("ro.build.version.release");
        CHECK(!sdk.empty(), "empty ro.build.version.sdk");
        auto props = dev.getProps();
        CHECK(props.count("ro.build.version.sdk") && props["ro.build.version.sdk"] == sdk, "getProps mismatch");
        return "Android " + rel + " (SDK " + sdk + "), " + std::to_string(props.size()) + " props";
    });

    test("raw stream: shell:", [&]
    {
        std::string out = dev.openStream("shell:echo raw-stream").readAll();
        CHECK(out.find("raw-stream") != std::string::npos, "got '" + out + "'");
        return std::string();
    });

    test("refused service throws", [&]
    {
        try
        {
            dev.openStream("no-such-service:");
        }
        catch (const adb::AdbError& e)
        {
            return std::string("AdbError: ") + e.what();
        }
        throw std::runtime_error("no exception");
    });

    // ------------------------------------------------------------------------
    // FILES
    // ------------------------------------------------------------------------
    dev.shell("rm -rf " + R + " && mkdir -p " + R);

    test("pushData / pullData", [&]
    {
        std::string data = "line1\nline2\n\x01\x02\xff binary";
        dev.pushData(data, R + "/small.txt");
        CHECK(dev.pullData(R + "/small.txt") == data, "content differs");
        return std::string();
    });

    const std::string big = randomBytes(8 * 1024 * 1024 + 123, 42);
    writeFile(tmp / "big.bin", big);

    test("push file (8 MB)", [&]
    {
        uint64_t last = 0;
        auto t0 = Clock::now();
        dev.push((tmp / "big.bin").string(), R + "/big.bin", [&](const std::string&, uint64_t done, uint64_t) { last = done; });
        auto d = Clock::now() - t0;
        CHECK(last == big.size(), "progress ended at " + std::to_string(last));
        return mbps(big.size(), d);
    });

    test("stat / exists", [&]
    {
        auto st = dev.stat(R + "/big.bin");
        CHECK(st.isRegular(), "not a regular file");
        CHECK(st.size == big.size(), "size " + std::to_string(st.size));
        CHECK(dev.exists(R + "/big.bin"), "exists() false");
        CHECK(!dev.exists(R + "/nope"), "exists() true for missing file");
        CHECK(dev.stat(R).isDirectory(), "dir not a directory");
        return std::string();
    });

    test("md5sum of pushed file on device", [&]
    {
        auto r = dev.shell("md5sum " + R + "/big.bin");
        CHECK(r.exitCode <= 0, "md5sum failed: " + r.err);
        return r.out.substr(0, 32);
    });

    test("pull file (8 MB)", [&]
    {
        auto t0 = Clock::now();
        dev.pull(R + "/big.bin", (tmp / "big_back.bin").string());
        auto d = Clock::now() - t0;
        CHECK(readFile(tmp / "big_back.bin") == big, "content differs");
        return mbps(big.size(), d);
    });

    test("pull into existing dir keeps name", [&]
    {
        fs::create_directories(tmp / "into");
        dev.pull(R + "/small.txt", (tmp / "into").string());
        CHECK(fs::exists(tmp / "into" / "small.txt"), "file not created as into/small.txt");
        return std::string();
    });

    test("exec-out is binary clean", [&]
    {
        std::string data = dev.execOut("cat " + R + "/big.bin");
        CHECK(data == big, "exec-out data differs (" + std::to_string(data.size()) + " bytes)");
        return std::string();
    });

    test("list", [&]
    {
        auto entries = dev.list(R);
        bool sawBig = false;
        for (auto& e : entries)
            if (e.name == "big.bin" && e.stat.size == big.size() && e.stat.isRegular())
                sawBig = true;
        CHECK(sawBig, "big.bin missing from listing (" + std::to_string(entries.size()) + " entries)");
        return std::to_string(entries.size()) + " entries";
    });

    test("push / pull directory tree", [&]
    {
        fs::path src = tmp / "tree";
        writeFile(src / "a.txt", "A");
        writeFile(src / "sub" / "b.txt", "BB");
        writeFile(src / "sub" / "deeper" / "c.bin", randomBytes(300000, 7));
        writeFile(src / fs::path(u8"unicode été.txt"), "utf8");
        fs::create_directories(src / "empty");

        dev.push(src.string(), R + "/tree");
        auto r = dev.shell("cd " + R + "/tree && find . | sort");
        CHECK(r.out.find("./empty") != std::string::npos, "empty dir missing on device:\n" + r.out);
        CHECK(r.out.find("./sub/deeper/c.bin") != std::string::npos, "nested file missing:\n" + r.out);

        fs::path back = tmp / "tree_back";
        dev.pull(R + "/tree", back.string());
        for (auto& e : fs::recursive_directory_iterator(src))
        {
            fs::path other = back / fs::relative(e.path(), src);
            CHECK(fs::exists(other), "missing after pull: " + other.string());
            if (e.is_regular_file())
                CHECK(readFile(e.path()) == readFile(other), "content differs: " + other.string());
        }
        return std::string();
    });

    test("pull missing file throws", [&]
    {
        try
        {
            dev.pull(R + "/does-not-exist", (tmp / "x").string());
        }
        catch (const adb::AdbError& e)
        {
            return std::string(e.what());
        }
        throw std::runtime_error("no exception");
    });

    // ------------------------------------------------------------------------
    // SCREEN / LOGS
    // ------------------------------------------------------------------------
    test("screencap", [&]
    {
        std::string png = dev.screencap();
        writeFile(tmp / "screen.png", png);
        return std::to_string(png.size()) + " bytes PNG -> " + (tmp / "screen.png").string();
    });

    test("logcat -d", [&]
    {
        int lines = 0;
        dev.logcat("-d -t 20", [&](std::string_view d)
        {
            for (char c : d)
                lines += c == '\n';
            return true;
        });
        CHECK(lines > 0, "no logcat output");
        return std::to_string(lines) + " lines";
    });

    // ------------------------------------------------------------------------
    // PACKAGES
    // ------------------------------------------------------------------------
    test("listPackages", [&]
    {
        auto all = dev.listPackages();
        auto third = dev.listPackages("-3");
        CHECK(!all.empty(), "no packages");
        return std::to_string(all.size()) + " packages, " + std::to_string(third.size()) + " third-party";
    });

    test("install (re-install smallest user app with -r)", [&]
    {
        // Pick the third-party app with the smallest APK set, pull it, install it back.
        std::string bestPkg;
        std::vector<std::string> bestPaths;
        uint64_t bestSize = UINT64_MAX;

        for (auto& pkg : dev.listPackages("-3"))
        {
            std::vector<std::string> paths;
            std::stringstream ss(dev.shell("pm path " + pkg).out);
            std::string line;
            uint64_t size = 0;
            while (std::getline(ss, line))
            {
                if (line.rfind("package:", 0) != 0)
                    continue;
                std::string p = line.substr(8);
                while (!p.empty() && (p.back() == '\r' || p.back() == '\n'))
                    p.pop_back();
                paths.push_back(p);
                size += dev.stat(p).size;
            }
            if (!paths.empty() && size < bestSize)
            {
                bestSize = size;
                bestPkg = pkg;
                bestPaths = paths;
            }
        }

        if (bestPkg.empty())
            throw Skip{ "no third-party apps on the device" };
        if (bestSize > 200ull * 1024 * 1024)
            throw Skip{ "smallest user app is over 200 MB" };

        std::vector<std::string> local;
        for (size_t i = 0; i < bestPaths.size(); i++)
        {
            fs::path p = tmp / "apk" / (std::to_string(i) + ".apk");
            fs::create_directories(p.parent_path());
            dev.pull(bestPaths[i], p.string());
            local.push_back(p.string());
        }

        auto t0 = Clock::now();
        std::string out = local.size() == 1 ? dev.install(local[0]) : dev.installMultiple(local);
        return bestPkg + " (" + std::to_string(local.size()) + " apk, " + std::to_string(bestSize / 1024) + " KB) -> " +
               out + ", " + mbps(bestSize, Clock::now() - t0);
    });

    test("uninstall unknown package reports failure", [&]
    {
        try
        {
            dev.uninstall("com.example.adbnative.doesnotexist");
        }
        catch (const adb::AdbError& e)
        {
            return std::string(e.what());
        }
        throw std::runtime_error("no exception");
    });

    // ------------------------------------------------------------------------
    // FORWARD / REVERSE
    // ------------------------------------------------------------------------
    test("forward tcp -> device", [&]
    {
        if (dev.shell("command -v nc").out.empty())
            throw Skip{ "no nc on device" };

        // one-shot server on the device
        std::thread server([&] { dev.shell("echo forward-ok | nc -l -p 29999"); });
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        adb::PortForward fwd = dev.forward(0, "tcp:29999");
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons((u_short)fwd.localPort());
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        CHECK(::connect(s, (sockaddr*)&a, sizeof(a)) == 0, "local connect failed");

        DWORD timeout = 5000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        std::string got;
        char buf[256];
        while (got.find('\n') == std::string::npos)
        {
            int r = recv(s, buf, sizeof(buf), 0);
            if (r <= 0)
                break;
            got.append(buf, r);
        }
        closesocket(s);
        fwd.stop();
        server.join();

        CHECK(got == "forward-ok\n", "got '" + got + "'");
        return "local port " + std::to_string(a.sin_port ? ntohs(a.sin_port) : 0);
    });

    test("reverse device -> local tcp", [&]
    {
        if (dev.shell("command -v nc").out.empty())
            throw Skip{ "no nc on device" };

        SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        bind(listener, (sockaddr*)&a, sizeof(a));
        listen(listener, 1);
        int len = sizeof(a);
        getsockname(listener, (sockaddr*)&a, &len);
        int localPort = ntohs(a.sin_port);

        int devicePort = dev.reverse("tcp:29998", localPort);
        std::string listing = dev.listReverse();

        std::string got;
        std::thread acceptor([&]
        {
            SOCKET c = accept(listener, nullptr, nullptr);
            if (c != INVALID_SOCKET)
            {
                const char reply[] = "pong\n";
                send(c, reply, sizeof(reply) - 1, 0);
                got = recvAll(c);
                closesocket(c);
            }
        });

        // toybox nc quits as soon as stdin hits EOF, so keep stdin open briefly
        auto r = dev.shell("(echo reverse-ok; sleep 1) | nc -w 3 127.0.0.1 29998");
        closesocket(listener);
        acceptor.join();
        dev.removeReverse("tcp:29998");

        CHECK(got == "reverse-ok\n", "server got '" + got + "', device out='" + r.out + "' err='" + r.err +
                                         "' exit=" + std::to_string(r.exitCode));
        CHECK(r.out.find("pong") != std::string::npos, "device got '" + r.out + "'");
        CHECK(listing.find("tcp:29998") != std::string::npos, "listReverse: '" + listing + "'");
        return "device port " + std::to_string(devicePort) + " -> local " + std::to_string(localPort);
    });

    // ------------------------------------------------------------------------
    // CONNECTION
    // ------------------------------------------------------------------------
    test("reconnect", [&]
    {
        dev.reconnect();
        CHECK(dev.alive(), "not alive after reconnect");
        CHECK(dev.shell("echo again").out == "again\n", "shell after reconnect failed");
        return std::string();
    });

    dev.shell("rm -rf " + R);
    fs::remove_all(tmp);

    std::cout << "\n" << passed << " passed, " << failed << " failed, " << skipped << " skipped\n";
    return failed == 0 ? 0 : 1;
}
