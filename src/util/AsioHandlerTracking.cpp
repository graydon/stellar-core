// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/AsioHandlerTracking.h"
#include "medida/metrics_registry.h"

#include <mutex>

namespace stellar {
namespace asio_tracking {

medida::MetricsRegistry *gApplicationMetrics = nullptr;
std::mutex gMetricsMutex;

// Called to install a single application-wide Metrics registry.
void setApplicationMetrics(medida::MetricsRegistry *r)
{
    std::lock_guard<std::mutex> guard(gMetricsMutex);
    gApplicationMetrics = r;
}

void
TrackedHandler::trackStep(TrackedHandler::Step step) const
{
    std::lock_guard<std::mutex> guard(gMetricsMutex);
    if (gApplicationMetrics)
    {
        auto now = std::chrono::system_clock::now();
        auto dur = now - mLastStepTime;
        switch (step)
        {
        case Step::Issued:
            if (mPendingTimer)
                mPendingTimer->Update(dur);
            break;
        case Step::Completed:
            if (mRunningTimer)
                mRunningTimer->Update(dur);
            break;
        case Step::Handled:
            if (mHandledTimer)
                mHandledTimer->Update(dur);
            break;
        }
        mLastStepTime = now;
    }
}

// Called when initializing tracking.
void init()
{
}

// Called when a TrackedHandler is created.
void creation(asio::execution_context& ctx,
              TrackedHandler& h,
              const char* object_type, void* object,
              std::uintmax_t native_handle, const char* op_name)
{
    std::lock_guard<std::mutex> guard(gMetricsMutex);
    if (gApplicationMetrics)
    {
        h.mLastStepTime = std::chrono::system_clock::now();
        h.mPendingTimer =
            &gApplicationMetrics->NewTimer({"asio", object_type, op_name, "pending"});
        h.mRunningTimer =
            &gApplicationMetrics->NewTimer({"asio", object_type, op_name, "running"});
        h.mHandledTimer =
            &gApplicationMetrics->NewTimer({"asio", object_type, op_name, "handled"});
    }
    else
    {
        // Explicitly blank the pointer fields; asio recycles handlers without
        // (re)constructing them.
        h.mPendingTimer = nullptr;
        h.mRunningTimer = nullptr;
        h.mHandledTimer = nullptr;
    }
}

// Called when an operation occurs that is not associated with a TrackedHandler.
void operation(asio::execution_context& ctx,
               const char* object_type, void* object,
               std::uintmax_t native_handle, const char* op_name)
{
}

// Called when some (reactor) object is registered.
void reactorRegistration(asio::execution_context& context,
                         std::uintmax_t native_handle, uintmax_t registration)
{
}

// Called when some (reactor) object is deregistered.
void reactorDeregistration(asio::execution_context& context,
                           std::uintmax_t native_handle, uintmax_t registration)
{
}

// Called when some (reactor) events are ready.
void reactorEvents(asio::execution_context& context,
                   std::uintmax_t registration, unsigned events)
{
}

// Called when some (reactor) object operation is performed.
void reactorOperation(const TrackedHandler& h,
                      const char* op_name, const asio::error_code& ec)
{
    h.trackStep(TrackedHandler::Step::Issued);
}

// Called when some (reactor) object operation is performed with a bytes_transfer count.
void reactorOperation(const TrackedHandler& h,
                      const char* op_name, const asio::error_code& ec,
                      std::size_t bytes_transferred)
{
    h.trackStep(TrackedHandler::Step::Issued);
}

}
}
