// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace adb
{
    namespace detail
    {
        struct StreamHandle;
    }

    // One bidirectional ADB stream to a device service ("shell:ls", "sync:",
    // "tcp:8080", ...). Copies share the same stream. The stream closes when
    // the last copy is destroyed or close() is called.
    class Stream
    {
    public:
        Stream() = default;
        explicit Stream(std::shared_ptr<detail::StreamHandle> handle)
            : handle(std::move(handle))
        {
        }

        bool valid() const { return handle != nullptr; }

        // Blocks until data arrives. Returns 0 once the device closed the stream.
        size_t read(void* buffer, size_t size);

        // Reads exactly size bytes or throws AdbError if the stream ends first.
        void readExact(void* buffer, size_t size);

        // Reads until the device closes the stream.
        std::string readAll();

        // Splits into max-payload packets; blocks while the device isn't ready for more.
        void write(const void* data, size_t size);
        void write(std::string_view data) { write(data.data(), data.size()); }

        void close();
        bool closed() const;

        // Largest chunk the device accepts in one packet.
        size_t maxPayload() const;

    private:
        std::shared_ptr<detail::StreamHandle> handle;
    };
}
