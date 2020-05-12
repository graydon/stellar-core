// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/Scheduler.h"
#include "util/Timer.h"
#include <cassert>

namespace stellar
{
using nsecs = std::chrono::nanoseconds;

const Scheduler::RelativeDeadline Scheduler::NEVER_DROP;
const Scheduler::RelativeDeadline Scheduler::DROP_ONLY_UNDER_LOAD;

using AbsoluteDeadline = VirtualClock::time_point;
const AbsoluteDeadline ABS_NEVER_DROP = AbsoluteDeadline::min();
const AbsoluteDeadline ABS_DROP_ONLY_UNDER_LOAD = AbsoluteDeadline::max();

class Scheduler::ActionQueue
    : public std::enable_shared_from_this<Scheduler::ActionQueue>
{
    struct Element
    {
        Action mAction;
        AbsoluteDeadline mDeadline;
        Element(VirtualClock& clock, Action&& action,
                Scheduler::RelativeDeadline rel)
            : mAction(std::move(action))
        {
            if (rel == Scheduler::NEVER_DROP)
            {
                mDeadline = ABS_NEVER_DROP;
            }
            else if (rel == Scheduler::DROP_ONLY_UNDER_LOAD)
            {
                mDeadline = ABS_DROP_ONLY_UNDER_LOAD;
            }
            else
            {
                mDeadline = clock.now() + rel;
            }
        }
        bool
        shouldDrop(bool overloaded, VirtualClock::time_point now,
                   Scheduler::Stats& stats) const
        {
            if (overloaded)
            {
                if (mDeadline != ABS_NEVER_DROP)
                {
                    stats.mActionsDroppedDueToOverload++;
                    return true;
                }
            }
            else
            {
                if (mDeadline != ABS_NEVER_DROP &&
                    mDeadline != ABS_DROP_ONLY_UNDER_LOAD && now > mDeadline)
                {
                    stats.mActionsDroppedDueToDeadline++;
                    return true;
                }
            }
            return false;
        }
    };

    std::string mName;
    nsecs mTotalService{0};
    std::chrono::steady_clock::time_point mLastService;
    std::deque<Element> mActions;

    // mIdleList is a reference to the mIdleList member of the Scheduler that
    // owns this ActionQueue. mIdlePosition is an iterator to the position in
    // that list that this ActionQueue occupies, or mIdleList.end() if it's
    // not in mIdleList.
    std::list<Qptr>& mIdleList;
    std::list<Qptr>::iterator mIdlePosition;

  public:
    ActionQueue(std::string const& name, std::list<Qptr>& idleList)
        : mName(name)
        , mLastService(std::chrono::steady_clock::time_point::max())
        , mIdleList(idleList)
        , mIdlePosition(mIdleList.end())
    {
    }

    bool
    isInIdleList() const
    {
        return mIdlePosition != mIdleList.end();
    }

    void
    addToIdleList()
    {
        assert(!isInIdleList());
        mIdleList.push_front(shared_from_this());
        mIdlePosition = mIdleList.begin();
    }

    void
    removeFromIdleList()
    {
        assert(isInIdleList());
        mIdleList.erase(mIdlePosition);
        mIdlePosition = mIdleList.end();
    }

    std::string const&
    name() const
    {
        return mName;
    }

    nsecs
    totalService() const
    {
        return mTotalService;
    }

    std::chrono::steady_clock::time_point
    lastService() const
    {
        return mLastService;
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
    tryTrim(size_t loadLimit, VirtualClock::time_point now,
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
    enqueue(VirtualClock& clock, Action&& action,
            Scheduler::RelativeDeadline deadline)
    {
        auto elt = Element(clock, std::move(action), deadline);
        mActions.emplace_back(std::move(elt));
    }

    void
    runNext(VirtualClock& clock, nsecs minTotalService)
    {
        auto before = clock.now();
        Action action = std::move(mActions.front().mAction);
        mActions.pop_front();
        action();
        auto after = clock.now();
        nsecs duration = std::chrono::duration_cast<nsecs>(after - before);
        mTotalService = std::max(mTotalService + duration, minTotalService);
        mLastService = after;
    }
};

Scheduler::Scheduler(VirtualClock& clock, size_t loadLimit,
                     std::chrono::nanoseconds totalServiceWindow,
                     std::chrono::nanoseconds maxIdleTime)
    : mRunnableActionQueues([](Qptr a, Qptr b) -> bool {
        return a->totalService() > b->totalService();
    })
    , mClock(clock)
    , mLoadLimit(loadLimit)
    , mTotalServiceWindow(totalServiceWindow)
    , mMaxIdleTime(maxIdleTime)
{
}

void
Scheduler::trimSingleActionQueue(Qptr q)
{
    VirtualClock::time_point now = mClock.now();
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
Scheduler::trimIdleActionQueues()
{
    if (mIdleActionQueues.empty())
    {
        return;
    }
    Qptr old = mIdleActionQueues.back();
    if (old->lastService() + mMaxIdleTime < mClock.now())
    {
        mAllActionQueues.erase(old->name());
        old->removeFromIdleList();
    }
}

void
Scheduler::enqueue(std::string&& name, Action&& action,
                   Scheduler::RelativeDeadline deadline)
{
    auto qi = mAllActionQueues.find(name);
    if (qi == mAllActionQueues.end())
    {
        mStats.mQueuesActivatedFromFresh++;
        auto q = std::make_shared<ActionQueue>(name, mIdleActionQueues);
        qi = mAllActionQueues.emplace(name, q).first;
        mRunnableActionQueues.push(qi->second);
    }
    else
    {
        if (qi->second->isInIdleList())
        {
            assert(qi->second->isEmpty());
            mStats.mQueuesActivatedFromIdle++;
            qi->second->removeFromIdleList();
            mRunnableActionQueues.push(qi->second);
        }
    }
    mStats.mActionsEnqueued++;
    qi->second->enqueue(mClock, std::move(action), deadline);
    mSize += 1;
}

size_t
Scheduler::runOne()
{
    trimIdleActionQueues();
    if (mRunnableActionQueues.empty())
    {
        return 0;
    }
    else
    {
        auto q = mRunnableActionQueues.top();
        mRunnableActionQueues.pop();
        trimSingleActionQueue(q);
        if (!q->isEmpty())
        {
            // We pass along a "minimum service time" floor that the service
            // time of the queue will be incremented to, at minimum.
            auto minTotalService = mMaxTotalService - mTotalServiceWindow;
            q->runNext(mClock, minTotalService);
            mMaxTotalService = std::max(q->totalService(), mMaxTotalService);
            mSize -= 1;
            mStats.mActionsDequeued++;
        }
        if (q->isEmpty())
        {
            mStats.mQueuesSuspended++;
            q->addToIdleList();
        }
        else
        {
            mRunnableActionQueues.push(q);
        }
        return 1;
    }
}

#ifdef BUILD_TESTS
std::shared_ptr<Scheduler::ActionQueue>
Scheduler::getExistingQueue(std::string const& name) const
{
    auto qi = mAllActionQueues.find(name);
    if (qi == mAllActionQueues.end())
    {
        return nullptr;
    }
    return qi->second;
}

std::string const&
Scheduler::nextQueueToRun() const
{
    static std::string empty;
    if (mRunnableActionQueues.empty())
    {
        return empty;
    }
    return mRunnableActionQueues.top()->name();
}
std::chrono::nanoseconds
Scheduler::totalService(std::string const& q) const
{
    auto eq = getExistingQueue(q);
    assert(eq);
    return eq->totalService();
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
