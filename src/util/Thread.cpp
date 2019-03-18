// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/Thread.h"
#include "util/Logging.h"

#ifdef _WIN32
#else
#include <pthread.h>
#endif

namespace stellar
{

#ifdef _WIN32

void
runWithLowPriority(std::thread& thread)
{
    auto native = thread.native_handle();
    auto ret = SetThreadPriority(native, THREAD_PRIORITY_BELOW_NORMAL);

    if (!ret)
    {
        CLOG(DEBUG, "Fs") << "Unable to set priority for thread: " << ret;
    }
}

#else

void
runWithLowPriority(std::thread& thread)
{
    auto native = thread.native_handle();
    int policy;
    sched_param param;

    auto ret = pthread_getschedparam(native, &policy, &param);
    if (ret)
    {
        CLOG(DEBUG, "Fs") << "Unable to get scheduler parameters for thread: "
                          << ret;
        return;
    }

    ret = pthread_setschedparam(native, SCHED_BATCH, &param);
    if (ret)
    {
        CLOG(DEBUG, "Fs") << "Unable to set scheduler parameters for thread: "
                          << ret;
        return;
    }
}

#endif
}
