// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "AdbKey.h"
#include "Protocol.h"
#include "Util.h"
#include "adb/Error.h"

#include <wincrypt.h>

#include <cstdio>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace adb::detail
{
    namespace
    {
        void check(NTSTATUS status, const char* what)
        {
            if (!BCRYPT_SUCCESS(status))
            {
                char hex[16];
                sprintf_s(hex, "0x%08lX", (unsigned long)status);
                throw AdbError(std::string(what) + " failed: " + hex);
            }
        }

        BCRYPT_ALG_HANDLE rsaProvider()
        {
            // Opened once, never closed: keys keep a reference to it.
            static BCRYPT_ALG_HANDLE alg = []
            {
                BCRYPT_ALG_HANDLE h = nullptr;
                check(BCryptOpenAlgorithmProvider(&h, BCRYPT_RSA_ALGORITHM, nullptr, 0), "BCryptOpenAlgorithmProvider");
                return h;
            }();
            return alg;
        }

        std::string base64(const void* data, size_t size)
        {
            DWORD len = 0;
            CryptBinaryToStringA((const BYTE*)data, (DWORD)size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
            std::string out(len, '\0');
            if (!CryptBinaryToStringA((const BYTE*)data, (DWORD)size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &len))
                throw AdbError("base64 encoding failed");
            out.resize(len);
            while (!out.empty() && out.back() == '\0')
                out.pop_back();
            return out;
        }

        std::vector<BYTE> unbase64(const std::string& text)
        {
            DWORD len = 0;
            if (!CryptStringToBinaryA(text.c_str(), (DWORD)text.size(), CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr))
                throw AdbError("adbkey: invalid base64");
            std::vector<BYTE> out(len);
            CryptStringToBinaryA(text.c_str(), (DWORD)text.size(), CRYPT_STRING_BASE64, out.data(), &len, nullptr, nullptr);
            out.resize(len);
            return out;
        }

        std::string envVar(const wchar_t* name)
        {
            wchar_t buf[MAX_PATH * 2];
            DWORD n = GetEnvironmentVariableW(name, buf, (DWORD)std::size(buf));
            if (n == 0 || n >= std::size(buf))
                return "";
            return fromPath(std::filesystem::path(std::wstring(buf, n)));
        }

        std::string readFile(const std::filesystem::path& p)
        {
            std::ifstream f(p, std::ios::binary);
            std::stringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }

        // Android's RSAPublicKey struct (libcrypto_utils android_pubkey.cpp):
        //   u32 modulus_size_words (64), u32 n0inv, u8 modulus[256] LE,
        //   u8 rr[256] LE (R^2 mod n, R = 2^2048), u32 exponent
        std::string encodeAndroidPublicKey(const std::vector<uint8_t>& modulusBE, uint32_t exponent)
        {
            constexpr int kWords = 64;
            if (modulusBE.size() != kWords * 4)
                throw AdbError("adbkey: only RSA-2048 keys are supported");

            uint32_t n[kWords + 1] = {};
            for (int i = 0; i < kWords * 4; i++)
            {
                uint8_t byte = modulusBE[modulusBE.size() - 1 - i];
                n[i / 4] |= uint32_t(byte) << (8 * (i % 4));
            }

            // n0inv = -1 / n[0] mod 2^32 (Newton iteration, n[0] is odd)
            uint32_t x = n[0];
            for (int i = 0; i < 5; i++)
                x *= 2 - n[0] * x;
            uint32_t n0inv = 0 - x;

            // rr = 2^4096 mod n by repeated doubling
            uint32_t r[kWords + 1] = { 1 };
            for (int bit = 0; bit < 2 * kWords * 32; bit++)
            {
                uint32_t carry = 0;
                for (int i = 0; i <= kWords; i++)
                {
                    uint32_t next = r[i] >> 31;
                    r[i] = (r[i] << 1) | carry;
                    carry = next;
                }

                bool geq = true;
                for (int i = kWords; i >= 0; i--)
                {
                    if (r[i] != n[i])
                    {
                        geq = r[i] > n[i];
                        break;
                    }
                }

                if (geq)
                {
                    uint64_t borrow = 0;
                    for (int i = 0; i <= kWords; i++)
                    {
                        uint64_t d = uint64_t(r[i]) - n[i] - borrow;
                        r[i] = uint32_t(d);
                        borrow = (d >> 63) & 1;
                    }
                }
            }

            std::string blob;
            putU32(blob, kWords);
            putU32(blob, n0inv);
            for (int i = 0; i < kWords; i++)
                putU32(blob, n[i]);
            for (int i = 0; i < kWords; i++)
                putU32(blob, r[i]);
            putU32(blob, exponent);
            return blob;
        }
    }

    // =========================================================================
    // LOAD / CREATE
    // =========================================================================
    std::string AdbKey::defaultPath()
    {
        std::filesystem::path dir;

        std::string userHome = envVar(L"ANDROID_USER_HOME");
        std::string sdkHome = envVar(L"ANDROID_SDK_HOME");
        if (!userHome.empty())
            dir = toPath(userHome);
        else if (!sdkHome.empty())
            dir = toPath(sdkHome) / ".android";
        else
            dir = toPath(envVar(L"USERPROFILE")) / ".android";

        return fromPath(dir / "adbkey");
    }

    std::shared_ptr<AdbKey> AdbKey::loadOrCreate(const std::string& path)
    {
        static std::mutex cacheMutex;
        static std::map<std::string, std::shared_ptr<AdbKey>> cache;

        std::lock_guard<std::mutex> lock(cacheMutex);
        if (auto it = cache.find(path); it != cache.end())
            return it->second;

        std::shared_ptr<AdbKey> k(new AdbKey());
        std::filesystem::path keyFile = toPath(path);
        std::filesystem::path pubFile = toPath(path + ".pub");

        if (std::filesystem::exists(keyFile))
        {
            k->importPem(readFile(keyFile));
            k->loadPublicParts();

            // adb sends adbkey.pub verbatim; do the same if it's there
            std::string pub = readFile(pubFile);
            while (!pub.empty() && (pub.back() == '\n' || pub.back() == '\r' || pub.back() == '\0' || pub.back() == ' '))
                pub.pop_back();
            if (!pub.empty())
                k->publicKeyText = pub;
        }
        else
        {
            k->generate();
            k->loadPublicParts();

            std::error_code ec;
            std::filesystem::create_directories(keyFile.parent_path(), ec);
            std::ofstream(keyFile, std::ios::binary) << k->exportPem();
            std::ofstream(pubFile, std::ios::binary) << k->publicKeyText << "\n";
        }

        cache[path] = k;
        return k;
    }

    AdbKey::~AdbKey()
    {
        if (key)
            BCryptDestroyKey(key);
    }

    void AdbKey::importPem(const std::string& pem)
    {
        std::string label, body;
        std::stringstream ss(pem);
        std::string line;
        while (std::getline(ss, line))
        {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                line.pop_back();

            if (startsWith(line, "-----BEGIN "))
                label = line.substr(11, line.size() - 11 - 5);
            else if (startsWith(line, "-----"))
                continue;
            else
                body += line;
        }

        std::vector<BYTE> der = unbase64(body);

        const BYTE* rsaDer = der.data();
        DWORD rsaLen = (DWORD)der.size();
        CRYPT_PRIVATE_KEY_INFO* pkcs8 = nullptr;
        DWORD size = 0;

        if (label == "PRIVATE KEY")
        {
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
                                     der.data(), (DWORD)der.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr, &pkcs8, &size))
                throw AdbError("adbkey: cannot decode PKCS#8 key");
            rsaDer = pkcs8->PrivateKey.pbData;
            rsaLen = pkcs8->PrivateKey.cbData;
        }
        else if (label != "RSA PRIVATE KEY")
        {
            throw AdbError("adbkey: unsupported PEM type '" + label + "'");
        }

        BCRYPT_RSAKEY_BLOB* blob = nullptr;
        DWORD blobLen = 0;
        BOOL ok = CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, rsaDer, rsaLen,
                                      CRYPT_DECODE_ALLOC_FLAG, nullptr, &blob, &blobLen);
        if (pkcs8)
            LocalFree(pkcs8);
        if (!ok)
            throw AdbError("adbkey: cannot decode RSA key");

        LPCWSTR type = blob->Magic == BCRYPT_RSAFULLPRIVATE_MAGIC ? BCRYPT_RSAFULLPRIVATE_BLOB : BCRYPT_RSAPRIVATE_BLOB;
        NTSTATUS status = BCryptImportKeyPair(rsaProvider(), nullptr, type, &key, (PUCHAR)blob, blobLen, 0);
        LocalFree(blob);
        check(status, "BCryptImportKeyPair");
    }

    void AdbKey::generate()
    {
        check(BCryptGenerateKeyPair(rsaProvider(), &key, 2048, 0), "BCryptGenerateKeyPair");
        check(BCryptFinalizeKeyPair(key, 0), "BCryptFinalizeKeyPair");
    }

    std::string AdbKey::exportPem() const
    {
        ULONG len = 0;
        check(BCryptExportKey(key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &len, 0), "BCryptExportKey");
        std::vector<BYTE> blob(len);
        check(BCryptExportKey(key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, blob.data(), len, &len, 0), "BCryptExportKey");

        BYTE* rsaDer = nullptr;
        DWORD rsaLen = 0;
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, blob.data(),
                                 CRYPT_ENCODE_ALLOC_FLAG, nullptr, &rsaDer, &rsaLen))
            throw AdbError("adbkey: cannot encode RSA key");

        // wrap PKCS#1 in PKCS#8, which is what adb writes ("BEGIN PRIVATE KEY")
        BYTE nullParams[] = { 0x05, 0x00 };
        CRYPT_PRIVATE_KEY_INFO info{};
        info.Version = 0;
        info.Algorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
        info.Algorithm.Parameters.cbData = sizeof(nullParams);
        info.Algorithm.Parameters.pbData = nullParams;
        info.PrivateKey.cbData = rsaLen;
        info.PrivateKey.pbData = rsaDer;

        BYTE* der = nullptr;
        DWORD derLen = 0;
        BOOL ok = CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, &info,
                                      CRYPT_ENCODE_ALLOC_FLAG, nullptr, &der, &derLen);
        LocalFree(rsaDer);
        if (!ok)
            throw AdbError("adbkey: cannot encode PKCS#8 key");

        std::string b64 = base64(der, derLen);
        LocalFree(der);

        std::string pem = "-----BEGIN PRIVATE KEY-----\n";
        for (size_t i = 0; i < b64.size(); i += 64)
            pem += b64.substr(i, 64) + "\n";
        pem += "-----END PRIVATE KEY-----\n";
        return pem;
    }

    void AdbKey::loadPublicParts()
    {
        ULONG len = 0;
        check(BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &len, 0), "BCryptExportKey");
        std::vector<BYTE> blob(len);
        check(BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), len, &len, 0), "BCryptExportKey");

        auto* hdr = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
        const BYTE* p = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);

        exponent = 0;
        for (ULONG i = 0; i < hdr->cbPublicExp; i++)
            exponent = (exponent << 8) | p[i];
        p += hdr->cbPublicExp;

        modulus.assign(p, p + hdr->cbModulus);

        std::string user = envVar(L"USERNAME");
        std::string host = envVar(L"COMPUTERNAME");
        std::string raw = encodeAndroidPublicKey(modulus, exponent);
        computedKeyText = base64(raw.data(), raw.size()) + " " + (user.empty() ? "unknown" : user) + "@" +
                          (host.empty() ? "unknown" : host);
        publicKeyText = computedKeyText;
    }

    // =========================================================================
    // AUTH
    // =========================================================================
    std::string AdbKey::sign(const std::string& token) const
    {
        BCRYPT_PKCS1_PADDING_INFO padding{ BCRYPT_SHA1_ALGORITHM };

        ULONG len = 0;
        check(BCryptSignHash(key, &padding, (PUCHAR)token.data(), (ULONG)token.size(), nullptr, 0, &len, BCRYPT_PAD_PKCS1),
              "BCryptSignHash");

        std::string sig(len, '\0');
        check(BCryptSignHash(key, &padding, (PUCHAR)token.data(), (ULONG)token.size(), (PUCHAR)sig.data(), len, &len,
                             BCRYPT_PAD_PKCS1),
              "BCryptSignHash");
        sig.resize(len);
        return sig;
    }

    std::string AdbKey::androidPublicKey() const
    {
        return publicKeyText;
    }
}
