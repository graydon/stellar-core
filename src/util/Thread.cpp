// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/Thread.h"
#include "util/Logging.h"

#ifdef _WIN32
#else
#include <unistd.h>
#endif

namespace stellar
{

#ifdef _WIN32

void
runCurrentThreadWithLowPriority()
{
    auto native = std::this_thread::get_id();
    auto ret = SetThreadPriority(native, THREAD_PRIORITY_BELOW_NORMAL);

    if (!ret)
    {
        CLOG(DEBUG, "Fs") << "Unable to set priority for thread: " << ret;
    }
}

#else

void
runCurrentThreadWithLowPriority()
{
    constexpr auto const LOW_PRIORITY_NICE = 5;

    auto newNice = nice(LOW_PRIORITY_NICE);
    if (newNice != LOW_PRIORITY_NICE)
    {
        CLOG(DEBUG, "Fs") << "Unable to run worker thread with low priority. "
                             "Normal priority will be used.";
    }
}

#endif
}
