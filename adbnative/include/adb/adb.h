// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once

// ============================================================================
//        NATIVE ADB - talks straight to adbd, no adb.exe / adb server
//    Supports: connect, shell (v2), exec-out, push/pull (files + dirs),
//              install / install-multiple / uninstall, reboot, root, tcpip,
//              remount, logcat, screencap, forward, reverse, raw streams
// ============================================================================

#include "Device.h"
#include "Discovery.h"
#include "Error.h"
#include "Forward.h"
#include "Stream.h"
#include "Types.h"
