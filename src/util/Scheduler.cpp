// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/Scheduler.h"
#include <cassert>

namespace stellar
{
using nsecs = std::chrono::nanoseconds;

const Scheduler::RelativeDeadline Scheduler::NEVER_DROP;
const Scheduler::RelativeDeadline Scheduler::DROP_ONLY_UNDER_LOAD;
const Scheduler::AbsoluteDeadline Scheduler::ABS_NEVER_DROP;
const Scheduler::AbsoluteDeadline Scheduler::ABS_DROP_ONLY_UNDER_LOAD;

class Scheduler::Queue
{
    struct Element
    {
        Action mAction;
        Scheduler::AbsoluteDeadline mDeadline;
        Element(Action&& action, Scheduler::RelativeDeadline rel)
            : mAction(std::move(action))
            , mDeadline(rel == Scheduler::NEVER_DROP
                            ? Scheduler::ABS_NEVER_DROP
                            : (rel == Scheduler::DROP_ONLY_UNDER_LOAD
                                   ? Scheduler::ABS_DROP_ONLY_UNDER_LOAD
                                   : std::chrono::steady_clock::now() + rel))
        {
        }
        bool
        shouldDrop(bool overloaded, Scheduler::AbsoluteDeadline now,
                   Scheduler::Stats& stats) const
        {
            if (overloaded)
            {
                if (mDeadline != Scheduler::ABS_NEVER_DROP)
                {
                    stats.mActionsDroppedDueToOverload++;
                    return true;
                }
            }
            else
            {
                if (mDeadline != Scheduler::ABS_NEVER_DROP &&
                    mDeadline != Scheduler::ABS_DROP_ONLY_UNDER_LOAD &&
                    now > mDeadline)
                {
                    stats.mActionsDroppedDueToDeadline++;
                    return true;
                }
            }
            return false;
        }
    };

    std::string mName;
    nsecs mServiceTime{0};
    std::deque<Element> mActions;

  public:
    Queue(std::string const& name) : mName(name)
    {
    }

    std::string const&
    name() const
    {
        return mName;
    }

    nsecs
    serviceTime() const
    {
        return mServiceTime;
    }

    size_t
    size() const
    {
        return mActions.size();
    }

    bool
    isEmpty() const
    {
        return mActions.empty();
    }

    size_t
    tryTrim(size_t loadLimit, Scheduler::AbsoluteDeadline now,
            Scheduler::Stats& stats)
    {
        if (!mActions.empty())
        {
            bool overloaded = size() > loadLimit;
            if (mActions.front().shouldDrop(overloaded, now, stats))
            {
                mActions.pop_front();
                return 1;
            }
            if (mActions.back().shouldDrop(overloaded, now, stats))
            {
                mActions.pop_back();
                return 1;
            }
        }
        return 0;
    }

    void
    enqueue(Action&& action, Scheduler::RelativeDeadline deadline)
    {
        auto elt = Element(std::move(action), deadline);
        mActions.emplace_back(std::move(elt));
    }

    void
    runNext(nsecs minServiceTime)
    {
        auto before = std::chrono::steady_clock::now();
        Action action = std::move(mActions.front().mAction);
        mActions.pop_front();
        action();
        auto after = std::chrono::steady_clock::now();
        nsecs duration = std::chrono::duration_cast<nsecs>(after - before);
        mServiceTime = std::max(mServiceTime + duration, minServiceTime);
    }
};

Scheduler::Scheduler(size_t loadLimit,
                     std::chrono::nanoseconds serviceTimeWindow)
    : mQueueQueue(
          [](std::shared_ptr<Queue> a, std::shared_ptr<Queue> b) -> bool {
              return a->serviceTime() > b->serviceTime();
          })
    , mLoadLimit(loadLimit)
    , mServiceTimeWindow(serviceTimeWindow)
{
}

void
Scheduler::trim(std::shared_ptr<Queue> q)
{
    Scheduler::AbsoluteDeadline now = std::chrono::steady_clock::now();
    while (true)
    {
        size_t trimmed = q->tryTrim(mLoadLimit, now, mStats);
        if (trimmed == 0)
        {
            return;
        }
        mSize -= trimmed;
    }
}

void
Scheduler::enqueue(std::string&& name, Action&& action,
                   Scheduler::RelativeDeadline deadline)
{
    auto qi = mQueues.find(name);
    if (qi == mQueues.end())
    {
        if (mQueueCache.exists(name))
        {
            mStats.mQueuesActivatedFromCache++;
            qi = mQueues.emplace(name, mQueueCache.get(name)).first;
        }
        else
        {
            mStats.mQueuesActivatedFromFresh++;
            auto q = std::make_shared<Queue>(name);
            mQueueCache.put(name, q);
            qi = mQueues.emplace(name, q).first;
        }
        mQueueQueue.push(qi->second);
    }
    mStats.mActionsEnqueued++;
    qi->second->enqueue(std::move(action), deadline);
    mSize += 1;
    trim(qi->second);
}

size_t
Scheduler::runOne()
{
    if (mQueueQueue.empty())
    {
        return 0;
    }
    else
    {
        auto q = mQueueQueue.top();
        mQueueQueue.pop();
        trim(q);
        if (!q->isEmpty())
        {
            // We pass along a "minimum service time" floor that the service
            // time of the queue will be incremented to, at minimum.
            auto minServiceTime = mMaxServiceTime - mServiceTimeWindow;
            q->runNext(minServiceTime);
            mMaxServiceTime = std::max(q->serviceTime(), mMaxServiceTime);
            mSize -= 1;
            mStats.mActionsDequeued++;
            trim(q);
        }
        if (q->isEmpty())
        {
            mStats.mQueuesSuspended++;
            mQueues.erase(q->name());
        }
        else
        {
            mQueueQueue.push(q);
        }
        return 1;
    }
}

#ifdef BUILD_TESTS
std::shared_ptr<Scheduler::Queue>
Scheduler::getExistingQueue(std::string const& name) const
{
    auto qi = mQueues.find(name);
    if (qi == mQueues.end())
    {
        if (mQueueCache.exists(name))
        {
            return mQueueCache.get(name);
        }
        else
        {
            return nullptr;
        }
    }
    return qi->second;
}

std::string const&
Scheduler::nextQueueToRun() const
{
    static std::string empty;
    if (mQueueQueue.empty())
    {
        return empty;
    }
    return mQueueQueue.top()->name();
}
std::chrono::nanoseconds
Scheduler::serviceTime(std::string const& q) const
{
    auto eq = getExistingQueue(q);
    assert(eq);
    return eq->serviceTime();
}

size_t
Scheduler::queueLength(std::string const& q) const
{
    auto eq = getExistingQueue(q);
    assert(eq);
    return eq->size();
}
#endif
}
