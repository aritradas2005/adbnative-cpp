// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <windows.h>
#include <bcrypt.h>

#include <memory>
#include <string>
#include <vector>

namespace adb::detail
{
    // ========================================================================
    //  RSA-2048 key in Google adb's format (~/.android/adbkey + adbkey.pub),
    //  implemented with Windows CNG only.
    // ========================================================================
    class AdbKey
    {
    public:
        // %ANDROID_USER_HOME%\adbkey, else %USERPROFILE%\.android\adbkey
        static std::string defaultPath();

        // Loads the PEM key, or generates and saves a new pair if it's missing.
        // Keys are cached per path for the life of the process.
        static std::shared_ptr<AdbKey> loadOrCreate(const std::string& path);

        ~AdbKey();
        AdbKey(const AdbKey&) = delete;
        AdbKey& operator=(const AdbKey&) = delete;

        // PKCS#1 v1.5 signature of the 20-byte AUTH token (treated as a SHA-1 digest).
        std::string sign(const std::string& token) const;

        // "<base64 android RSAPublicKey> user@host" — the adbkey.pub contents.
        std::string androidPublicKey() const;

        // Same, but always computed from the private key (ignores adbkey.pub).
        std::string computedPublicKey() const { return computedKeyText; }

    private:
        AdbKey() = default;

        void importPem(const std::string& pem);
        void generate();
        std::string exportPem() const;
        void loadPublicParts();

        BCRYPT_KEY_HANDLE key = nullptr;
        std::vector<uint8_t> modulus;    // big-endian
        uint32_t exponent = 0;
        std::string publicKeyText;
        std::string computedKeyText;
    };
}
