// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// ASIO is somewhat particular about when it gets included -- it wants to be the
// first to include <windows.h> -- so we try to include it before everything
// else.
#include "util/asio.h"
#include "bucket/Bucket.h"
#include "bucket/BucketApplicator.h"
#include "bucket/BucketList.h"
#include "bucket/BucketManager.h"
#include "bucket/BucketOutputIterator.h"
#include "bucket/LedgerCmp.h"
#include "crypto/Hex.h"
#include "crypto/Random.h"
#include "crypto/SHA.h"
#include "database/Database.h"
#include "lib/util/format.h"
#include "main/Application.h"
#include "medida/timer.h"
#include "util/Fs.h"
#include "util/LogSlowExecution.h"
#include "util/Logging.h"
#include "util/TmpDir.h"
#include "util/XDRStream.h"
#include "xdrpp/message.h"
#include <cassert>
#include <future>

namespace stellar
{

Bucket::Bucket(std::string const& filename, Hash const& hash)
    : mFilename(filename), mHash(hash)
{
    assert(filename.empty() || fs::exists(filename));
    if (!filename.empty())
    {
        CLOG(TRACE, "Bucket")
            << "Bucket::Bucket() created, file exists : " << mFilename;
        mSize = fs::size(filename);
    }
}

Bucket::Bucket()
{
}

Hash const&
Bucket::getHash() const
{
    return mHash;
}

std::string const&
Bucket::getFilename() const
{
    return mFilename;
}

size_t
Bucket::getSize() const
{
    return mSize;
}

bool
Bucket::containsBucketIdentity(BucketEntry const& id) const
{
    BucketEntryIdCmp cmp;
    BucketInputIterator iter(shared_from_this());
    while (iter)
    {
        if (!(cmp(*iter, id) || cmp(id, *iter)))
        {
            return true;
        }
        ++iter;
    }
    return false;
}

Bucket::EntryCounts
Bucket::countEntries() const
{
    Bucket::EntryCounts c{0, 0, 0};
    BucketInputIterator iter(shared_from_this());
    while (iter)
    {
        switch ((*iter).type())
        {
        case INITENTRY:
            ++c.nInit;
            break;
        case LIVEENTRY:
            ++c.nLive;
            break;
        case DEADENTRY:
            ++c.nDead;
            break;
        }
        ++iter;
    }
    return c;
}

void
Bucket::apply(Application& app) const
{
    BucketApplicator applicator(app, shared_from_this());
    BucketApplicator::Counters counters(std::chrono::system_clock::now());
    while (applicator)
    {
        applicator.advance(counters);
    }
}

std::vector<BucketEntry>
Bucket::convertToBucketEntry(std::vector<LedgerEntry> const& liveEntries,
                             bool isInit)
{
    std::vector<BucketEntry> live;
    live.reserve(liveEntries.size());
    for (auto const& e : liveEntries)
    {
        BucketEntry ce;
        ce.type(isInit ? INITENTRY : LIVEENTRY);
        ce.liveEntry() = e;
        live.push_back(ce);
    }
    std::sort(live.begin(), live.end(), BucketEntryIdCmp());
    return live;
}

std::vector<BucketEntry>
Bucket::convertToBucketEntry(std::vector<LedgerKey> const& deadEntries)
{
    std::vector<BucketEntry> dead;
    dead.reserve(deadEntries.size());
    for (auto const& e : deadEntries)
    {
        BucketEntry ce;
        ce.type(DEADENTRY);
        ce.deadEntry() = e;
        dead.push_back(ce);
    }
    std::sort(dead.begin(), dead.end(), BucketEntryIdCmp());
    return dead;
}

std::shared_ptr<Bucket>
Bucket::fresh(BucketManager& bucketManager,
              uint32_t protocolVersion,
              std::vector<LedgerEntry> const& initEntries,
              std::vector<LedgerEntry> const& liveEntries,
              std::vector<LedgerKey> const& deadEntries)
{
    // When building fresh buckets after protocol version 10 (i.e. version
    // 11-or-after) we differentiate INITENTRY from LIVEENTRY. In older
    // protocols, for compatibility sake, we mark both cases as LIVEENTRY.
    bool useInit =
        (protocolVersion >= FIRST_PROTOCOL_SUPPORTING_INITENTRY);

    auto live = convertToBucketEntry(initEntries, useInit);
    auto init = convertToBucketEntry(liveEntries, false);
    auto dead = convertToBucketEntry(deadEntries);

    BucketOutputIterator initOut(bucketManager.getTmpDir(), true);
    BucketOutputIterator liveOut(bucketManager.getTmpDir(), true);
    BucketOutputIterator deadOut(bucketManager.getTmpDir(), true);
    for (auto const& e : init)
    {
        initOut.put(e);
    }
    for (auto const& e : live)
    {
        liveOut.put(e);
    }
    for (auto const& e : dead)
    {
        deadOut.put(e);
    }
    auto initBucket = initOut.getBucket(bucketManager);
    auto liveBucket = liveOut.getBucket(bucketManager);
    auto deadBucket = deadOut.getBucket(bucketManager);

    std::shared_ptr<Bucket> bucket1, bucket2;
    {
        auto timer = LogSlowExecution("Bucket merge");
        bucket1 = Bucket::merge(bucketManager, initBucket, liveBucket);
    }
    {
        auto timer = LogSlowExecution("Bucket merge");
        bucket2 = Bucket::merge(bucketManager, bucket1, deadBucket);
    }
    return bucket2;
}

std::shared_ptr<Bucket>
Bucket::fresh(BucketManager& bucketManager,
              std::vector<LedgerEntry> const& liveEntries,
              std::vector<LedgerKey> const& deadEntries)
{
    return Bucket::fresh(bucketManager,
                         Bucket::FIRST_PROTOCOL_SUPPORTING_INITENTRY - 1,
                         {}, liveEntries, deadEntries);
}

inline void
maybePut(BucketOutputIterator& out, BucketEntry const& entry,
         std::vector<BucketInputIterator>& shadowIterators,
         bool keepShadowedLifecycleEntries)
{
    BucketEntryIdCmp cmp;
    for (auto& si : shadowIterators)
    {
        // Advance the shadowIterator while it's less than the candidate
        while (si && cmp(*si, entry))
        {
            ++si;
        }
        // We have stepped si forward to the point that either si is exhausted,
        // or else *si >= entry; we now check the opposite direction to see if
        // we have equality.
        if (si && !cmp(entry, *si))
        {
            // If so, then entry is shadowed in at least one level and we
            // will potentially not be doing a 'put', but rather returning
            // early. Whether or not we do a 'put' here, there is no need
            // to advance the other iterators, they will advance as and if
            // necessary in future calls to maybePut.
            //
            // In ledgers before protocol 11, keepShadowedLifecycleEntries
            // will be `false` and we will drop all shadowed entries here.
            //
            // In ledgers at-or-after protocol 11, it will be `true` which
            // means that we only elide 'put'ing an entry if it is in
            // LIVEENTRY state; we keep entries in DEADENTRY and INITENTRY
            // states, for two reasons:
            //
            //   - DEADENTRY is preserved to ensure that old live-or-init
            //     entries that were killed remain dead, are not brought
            //     back to life accidentally by having a newer shadow
            //     eliding their later DEADENTRY (tombstone). This is
            //     possible because newer shadowing entries may both refer
            //     to the same key as an older dead entry, and may occur as
            //     an INIT/DEAD pair that subsequently annihilate one
            //     another.
            //
            //     IOW we want to prevent the following scenario:
            //
            //       lev1:DEAD, lev2:INIT, lev3:DEAD, lev4:INIT
            //
            //     from turning into the following by shadowing:
            //
            //       lev1:DEAD, lev2:INIT, -elided-, lev4:INIT
            //
            //     and then the following by pairwise annihilation:
            //
            //       -annihilated-, -elided-, lev4:INIT
            //
            //   - INITENTRY is preserved to ensure that a DEADENTRY
            //     preserved by the previous rule does not itself
            //     shadow-out its own INITENTRY, but rather eventually ages
            //     and encounters (and is annihilated-by) that INITENTRY in
            //     an older level.  Thus preventing the accumulation of
            //     redundant tombstones.
            //
            // Note that this decision only controls whether to elide dead
            // entries due to _shadows_. There is a secondary elision of
            // dead entries at the _oldest level_ of the bucketlist that is
            // accompished through filtering at the BucketOutputIterator
            // level, and happens independent of ledger protocol version.
            if (entry.type() == LIVEENTRY || !keepShadowedLifecycleEntries)
                return;
        }
    }
    // Nothing shadowed.
    out.put(entry);
}

std::shared_ptr<Bucket>
Bucket::merge(BucketManager& bucketManager,
              std::shared_ptr<Bucket> const& oldBucket,
              std::shared_ptr<Bucket> const& newBucket,
              std::vector<std::shared_ptr<Bucket>> const& shadows,
              bool keepDeadEntries, uint32_t protocolVersion)
{
    // This is the key operation in the scheme: merging two (read-only)
    // buckets together into a new 3rd bucket, while calculating its hash,
    // in a single pass.

    // When merging buckets after protocol version 10 (i.e. version 11-or-after)
    // we switch shadowing-behaviour to a more conservative mode, in order to
    // support annihilation of INITENTRY and DEADENTRY pairs. See commentary
    // above in `maybePut`.
    bool keepShadowedLifecycleEntries =
        (protocolVersion >= FIRST_PROTOCOL_SUPPORTING_INITENTRY);

    assert(oldBucket);
    assert(newBucket);

    BucketInputIterator oi(oldBucket);
    BucketInputIterator ni(newBucket);

    std::vector<BucketInputIterator> shadowIterators(shadows.begin(),
                                                     shadows.end());

    auto timer = bucketManager.getMergeTimer().TimeScope();
    BucketOutputIterator out(bucketManager.getTmpDir(), keepDeadEntries);

    BucketEntryIdCmp cmp;
    while (oi || ni)
    {
        if (!ni)
        {
            // Out of new entries, take old entries.
            maybePut(out, *oi, shadowIterators, keepShadowedLifecycleEntries);
            ++oi;
        }
        else if (!oi)
        {
            // Out of old entries, take new entries.
            maybePut(out, *ni, shadowIterators, keepShadowedLifecycleEntries);
            ++ni;
        }
        else if (cmp(*oi, *ni))
        {
            // Next old-entry has smaller key, take it.
            maybePut(out, *oi, shadowIterators, keepShadowedLifecycleEntries);
            ++oi;
        }
        else if (cmp(*ni, *oi))
        {
            // Next new-entry has smaller key, take it.
            maybePut(out, *ni, shadowIterators, keepShadowedLifecycleEntries);
            ++ni;
        }
        else
        {
            // Old and new are for the same key and neither is INIT, take
            // the new key. If either key is INIT, we have to make some
            // adjustments:
            //
            //   old    |   new   |   result
            // ---------+---------+-----------
            //  INIT    |  INIT   |   error
            //  LIVE    |  INIT   |   error
            //  DEAD    |  INIT=x |   LIVE=x
            //  INIT=x  |  LIVE=y |   INIT=y
            //  INIT    |  DEAD   |   empty
            //
            //
            // What does this mean / why is it correct?
            //
            // Performing a merge between two same-key entries is about
            // maintaining two invariants:
            //
            //    1. From the perspective of a reader (eg. the database)
            //       the pre-merge pair of entries and post-merge single
            //       entry are indistinguishable, at least in terms that
            //       the reader/database cares about (liveness & value).
            //       This is the most important invariant since it's what
            //       makes the database have the right values!
            //
            //    2. From the perspective of chronological _sequences_ of
            //       lifecycle transitions, if an entry is in INIT state
            //       then its (chronological) predecessor state is DEAD
            //       either by the next-oldest state being an _explicit_
            //       DEAD tombstone, or by the INIT being the oldest state
            //       in the bucket list. This invariant allows us to assume
            //       that INIT followed by DEAD can be safely merged to
            //       empty (eliding the record) without revealing and
            //       reviving the key in some older non-DEAD state
            //       preceding the INIT.
            //
            // When merging a pair of non-INIT entries and taking the 'new'
            // value, invariant #1 is easy to see as preserved (an LSM tree
            // is defined as returning the newest value for an entry, so
            // preserving the newest of any pair is correct), and by
            // assumption neither entry is INIT-state so invariant #2 isn't
            // relevant / is unaffected.
            //
            // When merging a pair with an INIT, we can go case-by-case
            // through the table above and see that both invariants are
            // preserved:
            //
            //   - INIT,INIT and LIVE,INIT violate invariant #2, so by
            //     assumption should never be occurring.
            //
            //   - DEAD,INIT=x are indistinguishable from LIVE=x from the
            //     perspective of the reader, satisfying invariant #1. And
            //     since LIVE=x is not INIT-state anymore invariant #2
            //     is trivially preserved (does not apply).
            //
            //   - INIT=x,LIVE=y is indistinguishable from INIT=y from the
            //     perspective of the reader, satisfying invariant #1.  And
            //     assuming invariant #2 holds for INIT=x,LIVE=y, then it
            //     holds for INIT=y.
            //
            //   - INIT,DEAD is indistinguishable from absence-of-an-entry
            //     from the perspective of a reader, maintaining invariant
            //     #1, _if_ invariant #2 also holds (the predecessor state
            //     _before_ INIT was absent-or-DEAD). And invariant #2
            //     holds trivially _locally_ for this merge because there
            //     is no resulting state (i.e. it's not in INIT-state); and
            //     it holds slightly-less-trivially non-locally, because
            //     even if there is a subsequent (newer) INIT entry, the
            //     invariant is maintained for that newer entry too (it is
            //     still preceded by a DEAD state).

            BucketEntry const& oldEntry = *oi;
            BucketEntry const& newEntry = *ni;
            if (newEntry.type() == INITENTRY)
            {
                // The only legal new-is-INIT case is a merging a
                // delete+create to an update.
                assert(oldEntry.type() == DEADENTRY);
                BucketEntry newLive;
                newLive.type(LIVEENTRY);
                newLive.liveEntry() = newEntry.liveEntry();
                maybePut(out, newLive, shadowIterators,
                         keepShadowedLifecycleEntries);
            }
            else if (oldEntry.type() == INITENTRY)
            {
                // If we get here, new is not INIT; may be LIVE or DEAD.
                if (newEntry.type() == LIVEENTRY)
                {
                    // Merge a create+update to a fresher create.
                    BucketEntry newInit;
                    newInit.type(INITENTRY);
                    newInit.liveEntry() = newEntry.liveEntry();
                    maybePut(out, newInit, shadowIterators,
                             keepShadowedLifecycleEntries);
                }
                else
                {
                    // Merge a create+delete to nothingness.
                    assert(newEntry.type() == DEADENTRY);
                }
            }
            else
            {
                // Neither is in INIT state, take the newer one.
                maybePut(out, newEntry, shadowIterators,
                         keepShadowedLifecycleEntries);
            }
            ++oi;
            ++ni;
        }
    }
    return out.getBucket(bucketManager);
}
}
