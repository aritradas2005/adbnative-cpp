// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aritra Das

#pragma once
#include <memory>

namespace adb
{
    namespace detail
    {
        class ForwardImpl;
    }

    // An active "adb forward": a listener on 127.0.0.1:localPort whose
    // connections are tunnelled to a service on the device. Stops when
    // destroyed or stop() is called.
    class PortForward
    {
    public:
        PortForward() = default;
        explicit PortForward(std::shared_ptr<detail::ForwardImpl> impl)
            : impl(std::move(impl))
        {
        }

        PortForward(PortForward&&) noexcept = default;
        PortForward& operator=(PortForward&&) noexcept;
        PortForward(const PortForward&) = delete;
        PortForward& operator=(const PortForward&) = delete;
        ~PortForward();

        int localPort() const;
        bool active() const { return impl != nullptr; }
        void stop();

    private:
        std::shared_ptr<detail::ForwardImpl> impl;
    };
}
