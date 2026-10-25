# adbnative-cpp

A C++20 library for Windows that talks **directly to an Android emulator's `adbd`** — no `adb.exe`, no adb server on port 5037, no spawning console commands.

It implements the ADB wire protocol itself (handshake, RSA auth, stream multiplexing) and the device services on top of it: shell, file sync, package install, port forwarding and more.

```cpp
#include <adb/adb.h>

auto dev = adb::Device::connect("127.0.0.1:7555");   // or "emulator-5554"

auto r = dev.shell("getprop ro.build.version.release");
std::cout << r.out << " (exit " << r.exitCode << ")\n";

dev.push("C:/build/app.apk", "/data/local/tmp/app.apk");
dev.install("C:/build/app.apk");
std::string png = dev.screencap();
```

## Features

| adb command | adbnative |
|---|---|
| `adb devices` | `adb::findEmulators()` — scans the usual emulator ports in parallel |
| `adb connect host:port` | `adb::Device::connect("host:port")` |
| `adb shell <cmd>` | `dev.shell(cmd)` → stdout, stderr **and exit code** (shell protocol v2) |
| streaming shell | `dev.shellStream(cmd, onStdout, onStderr)` — return `false` to stop |
| `adb exec-out <cmd>` | `dev.execOut(cmd)` — binary-clean |
| `adb push` / `adb pull` | `dev.push(local, remote)` / `dev.pull(remote, local)` — files or whole directories, progress callback |
| `adb shell ls` / `stat` | `dev.list(dir)` / `dev.stat(path)` / `dev.exists(path)` |
| in-memory files | `dev.pushData(bytes, remote)` / `dev.pullData(remote)` |
| `adb install [-r]` | `dev.install(apk, {"-r"})` — streamed, no temp file on the device |
| `adb install-multiple` | `dev.installMultiple({base, splits...})` |
| `adb uninstall [-k]` | `dev.uninstall(pkg, keepData)` |
| `pm list packages` | `dev.listPackages("-3")` |
| `getprop` | `dev.getProp(name)` / `dev.getProps()` |
| `adb logcat` | `dev.logcat("-d -v brief", callback)` |
| `screencap -p` | `dev.screencap()` → PNG bytes |
| `adb forward` | `auto f = dev.forward(0, "tcp:8080");` — RAII, `f.localPort()` |
| `adb reverse` | `dev.reverse("tcp:8000", 8000)`, `removeReverse`, `listReverse` |
| `adb reboot [target]` | `dev.reboot("bootloader")` |
| `adb root` / `unroot` / `tcpip` / `usb` | `dev.root()` … then `dev.reconnect()` |
| `adb remount`, `disable-verity` | `dev.remount()`, `dev.disableVerity()`, `dev.enableVerity()` |
| anything else | `dev.openStream("service:...")` — raw bidirectional stream |

Every failure throws `adb::AdbError`; when the device refused something, `what()` contains the device's message.

`Device` objects can be copied (they share one connection) and used from several threads at once.

## Scope

- **Emulators / TCP only.** Works with Android Studio emulators, MuMu, Nox, MEmu, LDPlayer, BlueStacks, and any device after `adb tcpip 5555`. USB devices are not supported.
- **No Android 11+ wireless-debugging pairing** (`adb pair`, TLS).
- **Windows only** (Winsock + CNG). No third-party dependencies.

## Authentication

adbnative uses the same key as Google's adb: `%USERPROFILE%\.android\adbkey` (or `%ANDROID_USER_HOME%`). Emulators that already trust your PC connect without a prompt. If the key doesn't exist, a new RSA-2048 key pair is generated and saved in adb's format. Use `ConnectOptions::keyPath` to point elsewhere.

## Building

Requires Visual Studio 2026 (toolset v145) or change `PlatformToolset` in the `.vcxproj` files.

```bat
msbuild testADB.sln /p:Configuration=Release /p:Platform=x64
```

This produces `x64\Release\adbnative.lib` and the test runner `x64\Release\testADB.exe`.

To use the library in your own project: add `adbnative\include` to your include path, reference `adbnative.vcxproj` (or link `adbnative.lib`), and compile with C++20 and `/utf-8`. The needed Windows libraries (`ws2_32`, `bcrypt`, `crypt32`) are linked automatically.

All strings, including local file paths, are UTF-8.

## Tests

`testADB.exe` runs about 30 checks against a live emulator — shell, exit codes, 8 MB push/pull round trips, directory trees, install, forward/reverse, reconnect, and key handling:

```bat
x64\Release\testADB.exe                    :: auto-discover the first emulator
x64\Release\testADB.exe 127.0.0.1:7555     :: or pick one
```

The install test re-installs the smallest third-party app on the emulator with `-r` (data is kept). Destructive commands (reboot, root, tcpip, remount) are not exercised.

Set `ADBNATIVE_TRACE=1` to print every ADB packet to stderr.

## How it works

```
Device API          shell / sync / install / forward / reverse ...
Services            shell,v2,raw:  exec:  sync:  abb_exec:  reverse:forward:  ...
Connection          CNXN + AUTH handshake, reader thread, OPEN/OKAY/WRTE/CLSE streams
TcpTransport        Winsock, 127.0.0.1:<emulator adb port>
```

## License

[GPL-3.0-or-later](LICENSE). Programs that link this library and are distributed must also be GPL-compatible.
