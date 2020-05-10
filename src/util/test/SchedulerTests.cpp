// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/Scheduler.h"

#include "lib/catch.hpp"
#include "util/Logging.h"
#include <chrono>

using namespace stellar;

TEST_CASE("scheduler basic functionality", "[scheduler]")
{
    std::chrono::seconds window(10);
    size_t overload = 100;
    Scheduler sched(overload, window);

    std::string A("a"), B("b"), C("c");

    size_t nEvents{0};
    auto step = std::chrono::microseconds(1);
    auto microsleep = [&] {
        std::this_thread::sleep_for(step);
        ++nEvents;
    };

    sched.enqueue(std::string(A), microsleep, Scheduler::NEVER_DROP);

    CHECK(sched.size() == 1);
    CHECK(sched.nextQueueToRun() == A);
    CHECK(sched.totalService(A).count() == 0);
    CHECK(sched.queueLength(A) == 1);
    CHECK(sched.stats().mActionsEnqueued == 1);
    CHECK(sched.stats().mActionsDequeued == 0);
    CHECK(sched.stats().mActionsDroppedDueToOverload == 0);
    CHECK(sched.stats().mActionsDroppedDueToDeadline == 0);
    CHECK(sched.stats().mQueuesActivatedFromFresh == 1);
    CHECK(sched.stats().mQueuesActivatedFromCache == 0);
    CHECK(sched.stats().mQueuesSuspended == 0);

    CHECK(sched.runOne() == 1); // run A
    CHECK(nEvents == 1);
    CHECK(sched.totalService(A).count() != 0);
    CHECK(sched.stats().mActionsDequeued == 1);
    CHECK(sched.stats().mQueuesSuspended == 1);

    sched.enqueue(std::string(A), microsleep, Scheduler::NEVER_DROP);
    sched.enqueue(std::string(B), microsleep, Scheduler::NEVER_DROP);
    sched.enqueue(std::string(C), microsleep, Scheduler::NEVER_DROP);

    CHECK(sched.size() == 3);
    CHECK(sched.nextQueueToRun() != A);
    CHECK(sched.totalService(A).count() != 0);
    CHECK(sched.totalService(B).count() == 0);
    CHECK(sched.totalService(C).count() == 0);
    CHECK(sched.queueLength(A) == 1);
    CHECK(sched.queueLength(B) == 1);
    CHECK(sched.queueLength(C) == 1);
    CHECK(sched.stats().mActionsEnqueued == 4);
    CHECK(sched.stats().mActionsDroppedDueToOverload == 0);
    CHECK(sched.stats().mActionsDroppedDueToDeadline == 0);
    CHECK(sched.stats().mQueuesActivatedFromFresh == 3);
    CHECK(sched.stats().mQueuesActivatedFromCache == 1);

    auto aruntime = sched.totalService(A).count();
    CHECK(sched.runOne() == 1); // run B or C
    CHECK(sched.runOne() == 1); // run B or C
    CHECK(nEvents == 3);
    CHECK(sched.totalService(A).count() == aruntime);
    CHECK(sched.totalService(B).count() != 0);
    CHECK(sched.totalService(C).count() != 0);
    CHECK(sched.queueLength(A) == 1);
    CHECK(sched.queueLength(B) == 0);
    CHECK(sched.queueLength(C) == 0);
    CHECK(sched.stats().mActionsDequeued == 3);
    CHECK(sched.stats().mActionsDroppedDueToOverload == 0);
    CHECK(sched.stats().mActionsDroppedDueToDeadline == 0);
    CHECK(sched.stats().mQueuesSuspended == 3);

    CHECK(sched.runOne() == 1); // run A
    CHECK(nEvents == 4);
    CHECK(sched.queueLength(A) == 0);
    CHECK(sched.queueLength(B) == 0);
    CHECK(sched.queueLength(C) == 0);
    CHECK(sched.stats().mActionsDequeued == 4);
    CHECK(sched.stats().mQueuesSuspended == 4);
}

TEST_CASE("scheduler load shedding -- overload", "[scheduler]")
{
    std::chrono::seconds window(10);
    size_t overload = 100;
    Scheduler sched(overload, window);

    std::string A("a"), B("b"), C("c");

    size_t nEvents{0};
    auto step = std::chrono::microseconds(1);
    auto microsleep = [&] {
        std::this_thread::sleep_for(step);
        ++nEvents;
    };

    for (size_t i = 0; i < 10000; ++i)
    {
        sched.enqueue(std::string(A), microsleep,
                      Scheduler::DROP_ONLY_UNDER_LOAD);
        sched.enqueue(std::string(B), microsleep,
                      Scheduler::DROP_ONLY_UNDER_LOAD);
        sched.enqueue(std::string(C), microsleep,
                      Scheduler::DROP_ONLY_UNDER_LOAD);
        sched.runOne();
        sched.runOne();
        CHECK(sched.queueLength(A) <= overload);
        CHECK(sched.queueLength(B) <= overload);
        CHECK(sched.queueLength(C) <= overload);
    }
    while (sched.size() != 0)
    {
        sched.runOne();
    }
    // This test is a little bit nondeterministic since the queue's decisions
    // are ultimately based on real-time and the sleeps above. If it fails,
    // check that the numbers are at least nearly right and crank up the margin
    // of error a bit here. I've run it for several hours without problems
    // but machines can vary.
    double dropRatio = (((double)sched.stats().mActionsDroppedDueToOverload) /
                        ((double)sched.stats().mActionsDequeued));
    CHECK(dropRatio < 0.75);
    auto tot = sched.stats().mActionsDequeued +
               sched.stats().mActionsDroppedDueToOverload;
    CHECK(sched.stats().mActionsEnqueued == tot);
}

TEST_CASE("scheduler load shedding -- deadlines", "[scheduler]")
{
    std::chrono::seconds window(10);
    size_t overload = 100;
    Scheduler sched(overload, window);

    std::string A("a"), B("b"), C("c");

    size_t nEvents{0};
    auto step = std::chrono::microseconds(1);
    auto microsleep = [&] {
        std::this_thread::sleep_for(step);
        ++nEvents;
    };

    for (size_t i = 0; i < 10000; ++i)
    {
        sched.enqueue(std::string(A), microsleep,
                      std::chrono::microseconds(10));
        sched.enqueue(std::string(B), microsleep,
                      std::chrono::microseconds(10));
        sched.enqueue(std::string(C), microsleep,
                      std::chrono::microseconds(10));
        sched.runOne();
        sched.runOne();
        CHECK(sched.queueLength(A) <= overload);
        CHECK(sched.queueLength(B) <= overload);
        CHECK(sched.queueLength(C) <= overload);
    }
    while (sched.size() != 0)
    {
        sched.runOne();
    }
    // This test is a little bit nondeterministic since the queue's decisions
    // are ultimately based on real-time and the sleeps above. If it fails,
    // check that the numbers are at least nearly right and crank up the margin
    // of error a bit here. I've run it for several hours without problems
    // but machines can vary.
    double dropRatio = (((double)sched.stats().mActionsDroppedDueToDeadline) /
                        ((double)sched.stats().mActionsDequeued));
    CHECK(dropRatio > 1.0);
    CHECK(dropRatio < 3.0);
    auto tot = sched.stats().mActionsDequeued +
               sched.stats().mActionsDroppedDueToDeadline;
    CHECK(sched.stats().mActionsEnqueued == tot);
}
