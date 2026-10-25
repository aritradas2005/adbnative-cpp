// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#include "Connection.h"
#include "adb/Error.h"

namespace adb
{
    namespace
    {
        detail::StreamHandle& checked(const std::shared_ptr<detail::StreamHandle>& h)
        {
            if (!h)
                throw AdbError("invalid stream");
            return *h;
        }
    }

    size_t Stream::read(void* buffer, size_t size)
    {
        auto& h = checked(handle);
        return h.conn->read(*h.state, buffer, size);
    }

    void Stream::readExact(void* buffer, size_t size)
    {
        char* p = static_cast<char*>(buffer);
        while (size > 0)
        {
            size_t n = read(p, size);
            if (n == 0)
                throw AdbError("stream closed by device");
            p += n;
            size -= n;
        }
    }

    std::string Stream::readAll()
    {
        std::string out;
        char buffer[64 * 1024];
        while (true)
        {
            size_t n = read(buffer, sizeof(buffer));
            if (n == 0)
                break;
            out.append(buffer, n);
        }
        return out;
    }

    void Stream::write(const void* data, size_t size)
    {
        auto& h = checked(handle);
        h.conn->write(*h.state, data, size);
    }

    void Stream::close()
    {
        if (handle)
            handle->conn->closeStream(*handle->state);
    }

    bool Stream::closed() const
    {
        if (!handle)
            return true;

        std::lock_guard<std::mutex> lock(handle->state->mutex);
        return handle->state->phase == detail::StreamState::Phase::Closed && handle->state->rx.empty();
    }

    size_t Stream::maxPayload() const
    {
        return checked(handle).conn->info().maxPayload;
    }
}
