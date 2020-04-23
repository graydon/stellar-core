#pragma once

// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/RandomEvictionCache.h"

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <queue>

// This class implements a multi-queue scheduler for "actions" (deferred-work
// callbacks that some subsystem wants to run "soon" on the main thread),
// attempting to satisfy a variety of constraints and goals simultaneously:
//
//   0. Non-preemption: We have no ability to preempt actions while they're
//      running so this is a hard constraint, not just a goal.
//
//   1. Serial execution: within a queue, actions must run in the order they are
//      enqueued (or a subsequence thereof, if there are dropped actions) so
//      that clients can use queue-names to sequence logically-sequential
//      actions. Scheduling happens between queues but not within them.
//
//   2. Non-starvation: Everything enqueued (and not dropped) should run
//      eventually and the longer something waits, generally the more likely it
//      is to run.
//
//   3. Fairness: time given to each queue should be roughly equal, over time.
//
//   4. Deadlines and load-shedding: some actions are best-effort and should be
//      dropped when the system is under load, and others have deadlines after
//      which there's no point running them, they're just a waste. We want to
//      be able to drop either so they don't interfere with necessary actions.
//
//   5. Simplicity: clients of the scheduler shouldn't need to adjust a lot of
//      knobs, and the implementation should be as simple as possible and
//      exhibit as fixed a behaviour as possible. We don't want surprises in
//      dynamics.
//
//   6. Non-anticipation: many scheduling algorithms require more information
//      than we have, or are so-called "anticipation" algorithms that need to
//      know (or guess) the size or duration of the next action. We certainly
//      don't know these, and while we _could_ try to estimate them, the
//      algorithms that need anticipation can go wrong if fed bad estimates;
//      we'd prefer a non-anticipation (or "blind") approach that lacks this
//      risk.
//
// Given these goals and constraints, our current best guess is a lightly
// customized algorithm in a family called FB ("foreground-background" or
// "feedback") or LAS ("least attained service") or SET ("shortest elapsed
// time").
//
// For an idea with so many names, the algorithm is utterly simple: each queue
// tracks the accumulated runtime of all actions it has run, and on each step we
// run the next action in the queue with the lowest accumulated runtime (the
// queues themselves are therefore stored in an outer priority queue to enable
// quick retrieval of the next lowest queue).
//
// This has a few interesting properties:
//
//   - A low-frequency action (eg. a ledger close) will usually be scheduled
//     immediately, as it has built up some "credit" in its queue in the form of
//     zero new runtime in the period since its last run, lowering its
//     accumulation relative to other queues.
//
//   - A continuously-rescheduled multipart action (eg. bucket-apply or
//     catchup-replay) will quickly consume any "credit" it might have and be
//     throttled back to an equal time-share with other queues: since it spent a
//     long time on-CPU it will have to wait at least until everyone else has
//     had a similar amount of time before going again.
//
//   - If a very-short-duration action occurs it has little affect on anything
//     else, either its own queue or others, in the relative scheduling order. A
//     queue that's got lots of very-small actions (eg. just issuing a pile of
//     async IOs or writing to in-memory buffers) may run them _all_ before
//     anyone else gets to go, but that's ok precisely because they're very
//     small actions. The scheduler will shift to other queues exactly when a
//     queue uses up a _noticable amount of time_ relative to others.
//
// This is an old algorithm that was not used for a long time out of fear that
// it would starve long-duration actions; but it's received renewed study in
// recent years based on the observation that such starvation only occurs in
// certain theoretically-tidy but practically-rare distributions of action
// durations, and the distributions that occur in reality behave quite well
// under it.
//
// The customizations we make are minor:
//
//   - We put a floor on the cumulative durations; low cumulative durations
//     represent a form of "credit" that a queue might use in a burst if it were
//     to be suddenly full of ready actions, or continuously-reschedule itself,
//     so we make sure no queue can have less than some (steadily rising) floor.
//
//   - We encode deadlines in actions: those with a positive deadline are always
//     dropped -- unconditionally -- if they are ready to run after their
//     deadline, and may also be dropped conditionally if the system is under
//     load / the queue is too long. The sentinel "minimum deadline" value is
//     reserved to indicate a never-droppable action. To encode a "best effort"
//     action with no particular deadline that will be dropped only under load,
//     we set the deadline to the the maximal duration value.

namespace stellar
{

using Action = std::function<void()>;

class Scheduler
{
  public:
    struct Stats
    {
        size_t mActionsEnqueued{0};
        size_t mActionsDequeued{0};
        size_t mActionsDroppedDueToOverload{0};
        size_t mActionsDroppedDueToDeadline{0};
        size_t mQueuesActivatedFromFresh{0};
        size_t mQueuesActivatedFromCache{0};
        size_t mQueuesSuspended{0};
    };

    using RelativeDeadline = std::chrono::nanoseconds;
    using AbsoluteDeadline = std::chrono::steady_clock::time_point;
    static constexpr RelativeDeadline NEVER_DROP = RelativeDeadline::min();
    static constexpr RelativeDeadline DROP_ONLY_UNDER_LOAD =
        RelativeDeadline::max();
    static constexpr AbsoluteDeadline ABS_NEVER_DROP = AbsoluteDeadline::min();
    static constexpr AbsoluteDeadline ABS_DROP_ONLY_UNDER_LOAD =
        AbsoluteDeadline::max();

  private:
    class Queue;
    using Qptr = std::shared_ptr<Queue>;
    std::map<std::string, Qptr> mQueues;
    std::priority_queue<Qptr, std::vector<Qptr>,
                        std::function<bool(Qptr, Qptr)>>
        mQueueQueue;

    Stats mStats;

    // A queue is considered "overloaded" if its size is above the load limit.
    // This is a per-queue limit.
    size_t const mLoadLimit;

    // The serviceTime of any queue will always be advanced to at least this
    // duration behind mMaxServiceTime, to limit the amount of "suplus" service
    // time any given queue can acucmulate if it happens to go idle a long time.
    std::chrono::nanoseconds const mServiceTimeWindow;

    // Largest serviceTime seen in any queue. This number will continuously
    // advance as queues are serviced; it exists to serve as the upper limit
    // of the window, from which mServiceTimeWindow is subtracted to derive
    // the lower limit.
    std::chrono::nanoseconds mMaxServiceTime{0};

    // Sum of sizes of all the active queues. Maintained as items are enqueued
    // or run.
    size_t mSize{0};

    // We cache recent queues for a while after we empty them, so that we can
    // maintain a service-level estimate spanning their repeated activations.
    RandomEvictionCache<std::string, Qptr> mQueueCache{1024};

    void trim(Qptr q);

  public:
    Scheduler(size_t loadLimit, std::chrono::nanoseconds serviceTimeWindow);

    // Adds an action to the named queue with a given type and deadline.
    void enqueue(std::string&& name, Action&& action,
                 RelativeDeadline deadline);

    // Runs 0 or 1 action from the next Queue in the queue-of-queues.
    size_t runOne();

    size_t
    size() const
    {
        return mSize;
    }

    std::chrono::nanoseconds
    maxServiceTime() const
    {
        return mMaxServiceTime;
    }

    Stats const&
    stats() const
    {
        return mStats;
    }

#ifdef BUILD_TESTS
    // Testing interface
    Qptr getExistingQueue(std::string const& name) const;
    std::string const& nextQueueToRun() const;
    std::chrono::nanoseconds serviceTime(std::string const& q) const;
    size_t queueLength(std::string const& q) const;
#endif
};
}
