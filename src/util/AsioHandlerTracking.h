#pragma once

// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include <chrono>
#include <cstdint>
#include <system_error>

namespace medida {
class MetricsRegistry;
class Timer;
}

namespace asio {
class execution_context;
typedef std::error_code error_code;
}

namespace stellar {
namespace asio_tracking {

// This should only be set to an application's metrics if
// there is a single application and we've requested
// ASIO tracking.
void setApplicationMetrics(medida::MetricsRegistry *);

struct TrackedHandler
{
    char const *mObjectType;
    mutable std::chrono::system_clock::time_point mLastStepTime;

    // Timer for period between created and issued.
    medida::Timer *mPendingTimer;

    // Timer for period between issued and completed.
    medida::Timer *mRunningTimer;

    // Timer for period between completed and handled.
    medida::Timer *mHandledTimer;

    // An IO moves through a fixed sequence of steps:
    // created -> issued -> completed -> handled.
    enum class Step {
        Issued, Completed, Handled
    };

    void trackStep(Step s) const;
};

class Completion
{
    TrackedHandler mHandler;
public:
    explicit Completion(TrackedHandler const& h)
        : mHandler(h)
    {
    }
    Completion(Completion const&) = delete;
    Completion& operator=(Completion const&) = delete;

    template <class... Args>
    void invocationBegin(Args&&...)
    {
        mHandler.trackStep(TrackedHandler::Step::Completed);
    }
    void invocationEnd()
    {
        mHandler.trackStep(TrackedHandler::Step::Handled);
    }
};

void init();
void creation(asio::execution_context& ctx,
              TrackedHandler& h,
              const char* object_type, void* object,
              std::uintmax_t native_handle, const char* op_name);
void operation(asio::execution_context& ctx,
               const char* object_type, void* object,
               std::uintmax_t native_handle, const char* op_name);
void reactorRegistration(asio::execution_context& context,
                         std::uintmax_t native_handle, uintmax_t registration);
void reactorDeregistration(asio::execution_context& context,
                           std::uintmax_t native_handle, uintmax_t registration);
void reactorEvents(asio::execution_context& context,
                    std::uintmax_t registration, unsigned events);
void reactorOperation(const TrackedHandler& h,
                      const char* op_name, const asio::error_code& ec);
void reactorOperation(const TrackedHandler& h,
                      const char* op_name, const asio::error_code& ec,
                      std::size_t bytes_transferred);

}
}

#define ASIO_INHERIT_TRACKED_HANDLER                    \
    : public ::stellar::asio_tracking::TrackedHandler

#define ASIO_ALSO_INHERIT_TRACKED_HANDLER               \
    , public ::stellar::asio_tracking::TrackedHandler

#define ASIO_HANDLER_TRACKING_INIT              \
    ::stellar::asio_tracking::init()

#define ASIO_HANDLER_CREATION(args)             \
    ::stellar::asio_tracking::creation args

#define ASIO_HANDLER_COMPLETION(args)                           \
    ::stellar::asio_tracking::Completion trackedCompletion args

#define ASIO_HANDLER_INVOCATION_BEGIN(args)     \
    trackedCompletion.invocationBegin args

#define ASIO_HANDLER_INVOCATION_END             \
    trackedCompletion.invocationEnd()

#define ASIO_HANDLER_OPERATION(args)            \
    ::stellar::asio_tracking::operation args

#define ASIO_HANDLER_REACTOR_REGISTRATION(args)         \
    ::stellar::asio_tracking::reactorRegistration args

#define ASIO_HANDLER_REACTOR_DEREGISTRATION(args)           \
    ::stellar::asio_tracking::reactorDeregistration args

#define ASIO_HANDLER_REACTOR_READ_EVENT 1
#define ASIO_HANDLER_REACTOR_WRITE_EVENT 2
#define ASIO_HANDLER_REACTOR_ERROR_EVENT 4

#define ASIO_HANDLER_REACTOR_EVENTS(args)           \
    ::stellar::asio_tracking::reactorEvents args

#define ASIO_HANDLER_REACTOR_OPERATION(args)        \
    ::stellar::asio_tracking::reactorOperation args
