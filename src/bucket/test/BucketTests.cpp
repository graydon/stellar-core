// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// This file contains tests for individual Buckets, low-level invariants
// concerning the composition of buckets, the semantics of the merge
// operation(s), and the perfomance of merging and applying buckets to the
// database.

// ASIO is somewhat particular about when it gets included -- it wants to be the
// first to include <windows.h> -- so we try to include it before everything
// else.
#include "util/asio.h"
#include "bucket/BucketTests.h"
#include "bucket/Bucket.h"
#include "bucket/BucketInputIterator.h"
#include "ledger/LedgerTxn.h"
#include "ledger/test/LedgerTestUtils.h"
#include "lib/catch.hpp"
#include "main/Application.h"
#include "test/TestUtils.h"
#include "test/test.h"
#include "util/Fs.h"
#include "util/Logging.h"
#include "util/Timer.h"
#include "xdrpp/autocheck.h"

using namespace stellar;

namespace BucketTests
{

static std::ifstream::pos_type
fileSize(std::string const& name)
{
    assert(fs::exists(name));
    std::ifstream in(name, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

uint32_t
getAppLedgerVersion(Application& app)
{
    auto const& lcl = app.getLedgerManager().getLastClosedLedgerHeader();
    return lcl.header.ledgerVersion;
}

uint32_t
getAppLedgerVersion(Application::pointer app)
{
    return getAppLedgerVersion(*app);
}

void
for_versions_with_differing_bucket_logic(
    Config const& cfg, std::function<void(Config const&)> const& f)
{
    for_versions({Bucket::FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY - 1,
                  Bucket::FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY},
                 cfg, f);
}

EntryCounts::EntryCounts(std::shared_ptr<Bucket> bucket)
{
    BucketInputIterator iter(bucket);
    if (iter.seenMetadata())
    {
        ++nMeta;
    }
    while (iter)
    {
        switch ((*iter).type())
        {
        case INITENTRY:
            ++nInit;
            break;
        case LIVEENTRY:
            ++nLive;
            break;
        case DEADENTRY:
            ++nDead;
            break;
        case METAENTRY:
            // This should never happen: only the first record can be METAENTRY
            // and it is counted above.
            abort();
        }
        ++iter;
    }
}

size_t
countEntries(std::shared_ptr<Bucket> bucket)
{
    EntryCounts e(bucket);
    return e.sum();
}
}

using namespace BucketTests;

TEST_CASE("file backed buckets", "[bucket][bucketbench]")
{
    VirtualClock clock;
    Config const& cfg = getTestConfig();
    for_versions_with_differing_bucket_logic(cfg, [&](Config const& cfg) {
        Application::pointer app = createTestApplication(clock, cfg);

        autocheck::generator<LedgerKey> deadGen;
        CLOG(DEBUG, "Bucket") << "Generating 10000 random ledger entries";
        std::vector<LedgerEntry> live(9000);
        std::vector<LedgerKey> dead(1000);
        for (auto& e : live)
            e = LedgerTestUtils::generateValidLedgerEntry(3);
        for (auto& e : dead)
            e = deadGen(3);
        CLOG(DEBUG, "Bucket") << "Hashing entries";
        std::shared_ptr<Bucket> b1 = Bucket::fresh(
            app->getBucketManager(), getAppLedgerVersion(app), {}, live, dead);
        for (uint32_t i = 0; i < 5; ++i)
        {
            CLOG(DEBUG, "Bucket") << "Merging 10000 new ledger entries into "
                                  << (i * 10000) << " entry bucket";
            for (auto& e : live)
                e = LedgerTestUtils::generateValidLedgerEntry(3);
            for (auto& e : dead)
                e = deadGen(3);
            {
                b1 = Bucket::merge(app->getBucketManager(), b1,
                                   Bucket::fresh(app->getBucketManager(),
                                                 getAppLedgerVersion(app), {},
                                                 live, dead),
                                   /*shadows=*/{},
                                   /*keepDeadEntries*/ true);
            }
        }
        CLOG(DEBUG, "Bucket")
            << "Spill file size: " << fileSize(b1->getFilename());
    });
}

TEST_CASE("merging bucket entries", "[bucket]")
{
    VirtualClock clock;
    Config const& cfg = getTestConfig();
    for_versions_with_differing_bucket_logic(cfg, [&](Config const& cfg) {
        Application::pointer app = createTestApplication(clock, cfg);

        LedgerEntry liveEntry;
        LedgerKey deadEntry;

        autocheck::generator<bool> flip;

        SECTION("dead account entry annihilates live account entry")
        {
            liveEntry.data.type(ACCOUNT);
            liveEntry.data.account() =
                LedgerTestUtils::generateValidAccountEntry(10);
            deadEntry.type(ACCOUNT);
            deadEntry.account().accountID = liveEntry.data.account().accountID;
            std::vector<LedgerEntry> live{liveEntry};
            std::vector<LedgerKey> dead{deadEntry};
            std::shared_ptr<Bucket> b1 =
                Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app),
                              {}, live, dead);
            CHECK(countEntries(b1) == 1);
        }

        SECTION("dead trustline entry annihilates live trustline entry")
        {
            liveEntry.data.type(TRUSTLINE);
            liveEntry.data.trustLine() =
                LedgerTestUtils::generateValidTrustLineEntry(10);
            deadEntry.type(TRUSTLINE);
            deadEntry.trustLine().accountID =
                liveEntry.data.trustLine().accountID;
            deadEntry.trustLine().asset = liveEntry.data.trustLine().asset;
            std::vector<LedgerEntry> live{liveEntry};
            std::vector<LedgerKey> dead{deadEntry};
            std::shared_ptr<Bucket> b1 =
                Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app),
                              {}, live, dead);
            CHECK(countEntries(b1) == 1);
        }

        SECTION("dead offer entry annihilates live offer entry")
        {
            liveEntry.data.type(OFFER);
            liveEntry.data.offer() =
                LedgerTestUtils::generateValidOfferEntry(10);
            deadEntry.type(OFFER);
            deadEntry.offer().sellerID = liveEntry.data.offer().sellerID;
            deadEntry.offer().offerID = liveEntry.data.offer().offerID;
            std::vector<LedgerEntry> live{liveEntry};
            std::vector<LedgerKey> dead{deadEntry};
            std::shared_ptr<Bucket> b1 =
                Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app),
                              {}, live, dead);
            CHECK(countEntries(b1) == 1);
        }

        SECTION("random dead entries annihilates live entries")
        {
            std::vector<LedgerEntry> live(100);
            std::vector<LedgerKey> dead;
            for (auto& e : live)
            {
                e = LedgerTestUtils::generateValidLedgerEntry(10);
                if (flip())
                {
                    dead.push_back(LedgerEntryKey(e));
                }
            }
            std::shared_ptr<Bucket> b1 =
                Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app),
                              {}, live, dead);
            EntryCounts e(b1);
            CHECK(e.sum() == live.size());
            CLOG(DEBUG, "Bucket") << "post-merge live count: " << e.nLive
                                  << " of " << live.size();
            CHECK(e.nLive == live.size() - dead.size());
        }

        SECTION("random live entries overwrite live entries in any order")
        {
            std::vector<LedgerEntry> live(100);
            std::vector<LedgerKey> dead;
            for (auto& e : live)
            {
                e = LedgerTestUtils::generateValidLedgerEntry(10);
            }
            std::shared_ptr<Bucket> b1 =
                Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app),
                              {}, live, dead);
            std::random_shuffle(live.begin(), live.end());
            size_t liveCount = live.size();
            for (auto& e : live)
            {
                if (flip())
                {
                    e = LedgerTestUtils::generateValidLedgerEntry(10);
                    ++liveCount;
                }
            }
            std::shared_ptr<Bucket> b2 =
                Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app),
                              {}, live, dead);
            std::shared_ptr<Bucket> b3 =
                Bucket::merge(app->getBucketManager(), b1, b2,
                              /*shadows=*/{}, /*keepDeadEntries*/ true);
            CHECK(countEntries(b3) == liveCount);
        }
    });
}

static LedgerEntry
generateAccount()
{
    LedgerEntry e;
    e.data.type(ACCOUNT);
    e.data.account() = LedgerTestUtils::generateValidAccountEntry(10);
    return e;
}

static LedgerEntry
generateSameAccountDifferentState(std::vector<LedgerEntry> const& others)
{
    assert(
        std::all_of(others.begin(), others.end(), [](LedgerEntry const& other) {
            return other.data.type() == ACCOUNT;
        }));
    assert(!others.empty());
    while (true)
    {
        auto e = generateAccount();
        e.data.account().accountID = others[0].data.account().accountID;
        if (std::none_of(others.begin(), others.end(),
                         [&](LedgerEntry const& other) { return e == other; }))
        {
            return e;
        }
    }
}

static LedgerEntry
generateDifferentAccount(std::vector<LedgerEntry> const& others)
{
    assert(
        std::all_of(others.begin(), others.end(), [](LedgerEntry const& other) {
            return other.data.type() == ACCOUNT;
        }));
    while (true)
    {
        auto e = generateAccount();
        if (std::none_of(others.begin(), others.end(),
                         [&](LedgerEntry const& other) {
                             return e.data.account().accountID ==
                                    other.data.account().accountID;
                         }))
        {
            return e;
        }
    }
}

TEST_CASE("merging bucket entries with initentry", "[bucket][initentry]")
{
    VirtualClock clock;
    Config const& cfg = getTestConfig();
    for_versions_with_differing_bucket_logic(cfg, [&](Config const& cfg) {
        CLOG(INFO, "Bucket") << "=== starting test app == ";
        Application::pointer app = createTestApplication(clock, cfg);
        auto& bm = app->getBucketManager();
        auto vers = getAppLedgerVersion(app);

        // Whether we're in the era of supporting or not-supporting INITENTRY.
        bool initEra =
            (vers >= Bucket::FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY);

        CLOG(INFO, "Bucket") << "=== finished buckets for initial account == ";

        LedgerEntry liveEntry = generateAccount();
        LedgerEntry liveEntry2 = generateSameAccountDifferentState({liveEntry});
        LedgerEntry liveEntry3 =
            generateSameAccountDifferentState({liveEntry, liveEntry2});
        LedgerEntry otherLiveA = generateDifferentAccount({liveEntry});
        LedgerEntry otherLiveB =
            generateDifferentAccount({liveEntry, otherLiveA});
        LedgerEntry otherLiveC =
            generateDifferentAccount({liveEntry, otherLiveA, otherLiveB});
        LedgerEntry initEntry = generateSameAccountDifferentState(
            {liveEntry, liveEntry2, liveEntry3});
        LedgerEntry initEntry2 = generateSameAccountDifferentState(
            {initEntry, liveEntry, liveEntry2, liveEntry3});
        LedgerEntry otherInitA = generateDifferentAccount({initEntry});
        LedgerKey deadEntry = LedgerEntryKey(liveEntry);

        SECTION("dead and init account entries merge correctly")
        {
            auto b1 = Bucket::fresh(bm, vers, {initEntry}, {}, {deadEntry});
            // In initEra, the INIT will make it through fresh() to the bucket,
            // and mutually annihilate on contact with the DEAD, leaving 0
            // entries. Pre-initEra, the INIT will downgrade to a LIVE during
            // fresh(), and that will be killed by the DEAD, leaving 1
            // (tombstone) entry.
            EntryCounts e(b1);
            CHECK(e.nInit == 0);
            CHECK(e.nLive == 0);
            if (initEra)
            {
                CHECK(e.nMeta == 1);
                CHECK(e.nDead == 0);
            }
            else
            {
                CHECK(e.nMeta == 0);
                CHECK(e.nDead == 1);
            }
        }

        SECTION("dead and init entries merge with intervening live entries "
                "correctly")
        {
            auto b1 =
                Bucket::fresh(bm, vers, {initEntry}, {liveEntry}, {deadEntry});
            // The same thing should happen here as above, except that the INIT
            // will merge-over the LIVE during fresh().
            EntryCounts e(b1);
            CHECK(e.nInit == 0);
            CHECK(e.nLive == 0);
            if (initEra)
            {
                CHECK(e.nMeta == 1);
                CHECK(e.nDead == 0);
            }
            else
            {
                CHECK(e.nMeta == 0);
                CHECK(e.nDead == 1);
            }
        }

        SECTION("dead and init entries annihilate multiple live entries")
        {
            auto b1 =
                Bucket::fresh(bm, vers, {initEntry},
                              {liveEntry, liveEntry2, liveEntry3}, {deadEntry});
            // Same deal here as above.
            EntryCounts e(b1);
            CHECK(e.nInit == 0);
            CHECK(e.nLive == 0);
            if (initEra)
            {
                CHECK(e.nMeta == 1);
                CHECK(e.nDead == 0);
            }
            else
            {
                CHECK(e.nMeta == 0);
                CHECK(e.nDead == 1);
            }
        }

        SECTION("dead and init entries annihilate multiple live entries via "
                "separate buckets")
        {
            auto bold = Bucket::fresh(bm, vers, {initEntry}, {}, {});
            auto bmed = Bucket::fresh(
                bm, vers, {}, {otherLiveA, otherLiveB, liveEntry, otherLiveC},
                {});
            auto bnew = Bucket::fresh(bm, vers, {}, {}, {deadEntry});
            EntryCounts eold(bold), emed(bmed), enew(bnew);
            if (initEra)
            {
                CHECK(eold.nMeta == 1);
                CHECK(emed.nMeta == 1);
                CHECK(enew.nMeta == 1);
                CHECK(eold.nInit == 1);
                CHECK(eold.nLive == 0);
            }
            else
            {
                CHECK(eold.nMeta == 0);
                CHECK(emed.nMeta == 0);
                CHECK(enew.nMeta == 0);
                CHECK(eold.nInit == 0);
                CHECK(eold.nLive == 1);
            }

            CHECK(eold.nDead == 0);

            CHECK(emed.nInit == 0);
            CHECK(emed.nLive == 4);
            CHECK(emed.nDead == 0);

            CHECK(enew.nInit == 0);
            CHECK(enew.nLive == 0);
            CHECK(enew.nDead == 1);

            auto bmerge1 = Bucket::merge(bm, bold, bmed, /*shadows=*/{},
                                         /*keepDeadEntries=*/true);
            auto bmerge2 = Bucket::merge(bm, bmerge1, bnew, /*shadows=*/{},
                                         /*keepDeadEntries=*/true);
            EntryCounts emerge1(bmerge1), emerge2(bmerge2);
            if (initEra)
            {
                CHECK(emerge1.nMeta == 1);
                CHECK(emerge1.nInit == 1);
                CHECK(emerge1.nLive == 3);

                CHECK(emerge2.nMeta == 1);
                CHECK(emerge2.nDead == 0);
            }
            else
            {
                CHECK(emerge1.nMeta == 0);
                CHECK(emerge1.nInit == 0);
                CHECK(emerge1.nLive == 4);

                CHECK(emerge2.nMeta == 0);
                CHECK(emerge2.nDead == 1);
            }
            CHECK(emerge1.nDead == 0);
            CHECK(emerge2.nInit == 0);
            CHECK(emerge2.nLive == 3);
        }

        SECTION("shadows influence lifecycle entries appropriately")
        {
            // In pre-11 versions, shadows _do_ eliminate lifecycle entries
            // (INIT/DEAD). In 11-and-after versions, shadows _don't_ eliminate
            // lifecycle entries.
            auto shadow = Bucket::fresh(bm, vers, {}, {liveEntry}, {});
            auto b1 = Bucket::fresh(bm, vers, {initEntry}, {}, {});
            auto b2 = Bucket::fresh(bm, vers, {otherInitA}, {}, {});
            auto merged = Bucket::merge(bm, b1, b2, /*shadows=*/{shadow},
                                        /*keepDeadEntries=*/true);
            EntryCounts e(merged);
            if (initEra)
            {
                CHECK(e.nMeta == 1);
                CHECK(e.nInit == 2);
                CHECK(e.nLive == 0);
                CHECK(e.nDead == 0);
            }
            else
            {
                CHECK(e.nMeta == 0);
                CHECK(e.nInit == 0);
                CHECK(e.nLive == 1);
                CHECK(e.nDead == 0);
            }
        }

        SECTION("shadowing does not revive dead entries")
        {
            // This is the first contrived example of what might go wrong if we
            // shadowed aggressively while supporting INIT+DEAD annihilation,
            // and why we had to change the shadowing behaviour when introducing
            // INIT. See comment in `maybePut` in Bucket.cpp.
            //
            // (level1 is newest here, level5 is oldest)
            auto level1 = Bucket::fresh(bm, vers, {}, {}, {deadEntry});
            auto level2 = Bucket::fresh(bm, vers, {initEntry2}, {}, {});
            auto level3 = Bucket::fresh(bm, vers, {}, {}, {deadEntry});
            auto level4 = Bucket::fresh(bm, vers, {}, {}, {});
            auto level5 = Bucket::fresh(bm, vers, {initEntry}, {}, {});

            // Do a merge between levels 4 and 3, with shadows from 2 and 1,
            // risking shadowing-out level 3. Level 4 is a placeholder here,
            // just to be a thing-to-merge-level-3-with in the presence of
            // shadowing from 1 and 2.
            auto merge43 =
                Bucket::merge(bm, level4, level3, {level2, level1}, true);
            EntryCounts e43(merge43);
            if (initEra)
            {
                // New-style, we preserve the dead entry.
                CHECK(e43.nMeta == 1);
                CHECK(e43.nInit == 0);
                CHECK(e43.nLive == 0);
                CHECK(e43.nDead == 1);
            }
            else
            {
                // Old-style, we shadowed-out the dead entry.
                CHECK(e43.nMeta == 0);
                CHECK(e43.nInit == 0);
                CHECK(e43.nLive == 0);
                CHECK(e43.nDead == 0);
            }

            // Do a merge between level 2 and 1, producing potentially
            // an annihilation of their INIT and DEAD pair.
            auto merge21 = Bucket::merge(bm, level2, level1, {}, true);
            EntryCounts e21(merge21);
            if (initEra)
            {
                // New-style, they mutually annihilate.
                CHECK(e21.nMeta == 1);
                CHECK(e21.nInit == 0);
                CHECK(e21.nLive == 0);
                CHECK(e21.nDead == 0);
            }
            else
            {
                // Old-style, we keep the tombstone around.
                CHECK(e21.nMeta == 0);
                CHECK(e21.nInit == 0);
                CHECK(e21.nLive == 0);
                CHECK(e21.nDead == 1);
            }

            // Do two more merges: one between the two merges we've
            // done so far, and then finally one with level 5.
            auto merge4321 = Bucket::merge(bm, merge43, merge21, {}, true);
            auto merge54321 = Bucket::merge(bm, level5, merge4321, {}, true);
            EntryCounts e54321(merge21);
            if (initEra)
            {
                // New-style, we should get a second mutual annihilation.
                CHECK(e54321.nMeta == 1);
                CHECK(e54321.nInit == 0);
                CHECK(e54321.nLive == 0);
                CHECK(e54321.nDead == 0);
            }
            else
            {
                // Old-style, the tombstone should clobber the live entry.
                CHECK(e54321.nMeta == 0);
                CHECK(e54321.nInit == 0);
                CHECK(e54321.nLive == 0);
                CHECK(e54321.nDead == 1);
            }
        }

        SECTION("shadowing does not eliminate init entries")
        {
            // This is the second less-bad but still problematic contrived
            // example of what might go wrong if we shadowed aggressively while
            // supporting INIT+DEAD annihilation, and why we had to change the
            // shadowing behaviour when introducing INIT. See comment in
            // `maybePut` in Bucket.cpp.
            //
            // (level1 is newest here, level3 is oldest)
            auto level1 = Bucket::fresh(bm, vers, {}, {}, {deadEntry});
            auto level2 = Bucket::fresh(bm, vers, {}, {liveEntry}, {});
            auto level3 = Bucket::fresh(bm, vers, {initEntry}, {}, {});

            // Do a merge between levels 3 and 2, with shadow from 1, risking
            // shadowing-out the init on level 3. Level 2 is a placeholder here,
            // just to be a thing-to-merge-level-3-with in the presence of
            // shadowing from 1.
            auto merge32 = Bucket::merge(bm, level3, level2, {level1}, true);
            EntryCounts e32(merge32);
            if (initEra)
            {
                // New-style, we preserve the init entry.
                CHECK(e32.nMeta == 1);
                CHECK(e32.nInit == 1);
                CHECK(e32.nLive == 0);
                CHECK(e32.nDead == 0);
            }
            else
            {
                // Old-style, we shadowed-out the live and init entries.
                CHECK(e32.nMeta == 0);
                CHECK(e32.nInit == 0);
                CHECK(e32.nLive == 0);
                CHECK(e32.nDead == 0);
            }

            // Now do a merge between that 3+2 merge and level 1, and we risk
            // collecting tombstones in the lower levels, which we're expressly
            // trying to _stop_ doing by adding INIT.
            auto merge321 = Bucket::merge(bm, merge32, level1, {}, true);
            EntryCounts e321(merge321);
            if (initEra)
            {
                // New-style, init meets dead and they annihilate.
                CHECK(e321.nMeta == 1);
                CHECK(e321.nInit == 0);
                CHECK(e321.nLive == 0);
                CHECK(e321.nDead == 0);
            }
            else
            {
                // Old-style, init was already shadowed-out, so dead
                // accumulates.
                CHECK(e321.nMeta == 0);
                CHECK(e321.nInit == 0);
                CHECK(e321.nLive == 0);
                CHECK(e321.nDead == 1);
            }
        }
    });
}

TEST_CASE("bucket apply", "[bucket]")
{
    VirtualClock clock;
    Config cfg(getTestConfig());
    for_versions_with_differing_bucket_logic(cfg, [&](Config const& cfg) {
        Application::pointer app = createTestApplication(clock, cfg);
        app->start();

        std::vector<LedgerEntry> live(10), noLive;
        std::vector<LedgerKey> dead, noDead;

        for (auto& e : live)
        {
            e.data.type(ACCOUNT);
            auto& a = e.data.account();
            a = LedgerTestUtils::generateValidAccountEntry(5);
            a.balance = 1000000000;
            dead.emplace_back(LedgerEntryKey(e));
        }

        std::shared_ptr<Bucket> birth =
            Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app), {},
                          live, noDead);

        std::shared_ptr<Bucket> death =
            Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app), {},
                          noLive, dead);

        CLOG(INFO, "Bucket")
            << "Applying bucket with " << live.size() << " live entries";
        birth->apply(*app);
        {
            auto count = app->getLedgerTxnRoot().countObjects(ACCOUNT);
            REQUIRE(count == live.size() + 1 /* root account */);
        }

        CLOG(INFO, "Bucket")
            << "Applying bucket with " << dead.size() << " dead entries";
        death->apply(*app);
        {
            auto count = app->getLedgerTxnRoot().countObjects(ACCOUNT);
            REQUIRE(count == 1 /* root account */);
        }
    });
}

TEST_CASE("bucket apply bench", "[bucketbench][!hide]")
{
    auto runtest = [](Config::TestDbMode mode) {
        VirtualClock clock;
        Config cfg(getTestConfig(0, mode));
        Application::pointer app = createTestApplication(clock, cfg);
        app->start();

        std::vector<LedgerEntry> live(100000);
        std::vector<LedgerKey> noDead;

        for (auto& l : live)
        {
            l.data.type(ACCOUNT);
            auto& a = l.data.account();
            a = LedgerTestUtils::generateValidAccountEntry(5);
        }

        std::shared_ptr<Bucket> birth =
            Bucket::fresh(app->getBucketManager(), getAppLedgerVersion(app), {},
                          live, noDead);

        CLOG(INFO, "Bucket")
            << "Applying bucket with " << live.size() << " live entries";
        // note: we do not wrap the `apply` call inside a transaction
        // as bucket applicator commits to the database incrementally
        birth->apply(*app);
    };

    SECTION("sqlite")
    {
        runtest(Config::TESTDB_ON_DISK_SQLITE);
    }
#ifdef USE_POSTGRES
    SECTION("postgresql")
    {
        runtest(Config::TESTDB_POSTGRESQL);
    }
#endif
}