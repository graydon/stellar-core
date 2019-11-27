// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/Hex.h"
#include "crypto/Random.h"
#include "history/HistoryArchiveManager.h"
#include "history/test/HistoryTestsUtils.h"
#include "lib/catch.hpp"
#include "main/Application.h"
#include "main/ApplicationUtils.h"
#include "test/TestUtils.h"
#include "test/test.h"
#include "xdr/Stellar-ledger.h"

using namespace stellar;

#ifndef _WIN32
TEST_CASE("LedgerCloseMetaStream file descriptor - LIVE_NODE",
          "[ledgerclosemetastreamlive]")
{
    // Step 1: open a writable file descriptor.
    TmpDirManager tdm(std::string("streamtmp-") + binToHex(randomBytes(8)));
    TmpDir td = tdm.tmpDir("streams");
    std::string path = td.getName() + "/stream.xdr";
    int fd = ::open(path.c_str(), O_CREAT | O_WRONLY, 0644);
    REQUIRE(fd != -1);

    // Step 2: pass it to an application and close some ledgers,
    // streaming ledgerCloseMeta to the file descriptor.
    auto cfg = getTestConfig();
    cfg.METADATA_OUTPUT_FILE_DESCRIPTOR = fd;
    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);
    app->start();
    while (app->getLedgerManager().getLastClosedLedgerNum() < 10)
    {
        clock.crank(true);
    }
    Hash hash = app->getLedgerManager().getLastClosedLedgerHeader().hash;
    while (!app->getLedgerManager().metadataBufferEmpty())
    {
        clock.crank(true);
    }
    app.reset();

    // Step 3: reopen the file as an XDR stream and read back the LCMs
    // and check they have the expected content.
    XDRInputFileStream stream;
    stream.open(path);
    LedgerCloseMeta lcm;
    size_t nLcm = 1;
    while (stream && stream.readOne(lcm))
    {
        ++nLcm;
    }
    REQUIRE(nLcm == 10);
    REQUIRE(lcm.v0().ledgerHeader.hash == hash);
}

TEST_CASE("LedgerCloseMetaStream file descriptor - REPLAY_HISTORY_FOR_METADATA",
          "[ledgerclosemetastreamreplay]")
{
    // Step 1: generate some history for replay.
    using namespace stellar::historytestutils;
    TmpDirHistoryConfigurator tCfg;
    {
        Config genCfg = getTestConfig(0);
        VirtualClock genClock;
        genCfg = tCfg.configure(genCfg, true);
        auto genApp = createTestApplication(genClock, genCfg);
        auto& genHam = genApp->getHistoryArchiveManager();
        genHam.initializeHistoryArchive(tCfg.getArchiveDirName());
        for (size_t i = 0; i < 100; ++i)
        {
            genClock.crank(false);
        }
        genApp->start();
        auto& genHm = genApp->getHistoryManager();
        while (genHm.getPublishSuccessCount() < 5)
        {
            genClock.crank(true);
        }
        while (genClock.cancelAllEvents() ||
               genApp->getProcessManager().getNumRunningProcesses() > 0)
        {
            genClock.crank(false);
        }
    }

    // Step 2: open a writable file descriptor.
    TmpDirManager tdm(std::string("streamtmp-") + binToHex(randomBytes(8)));
    TmpDir td = tdm.tmpDir("streams");
    std::string path = td.getName() + "/stream.xdr";
    int fd = ::open(path.c_str(), O_CREAT | O_WRONLY, 0644);
    REQUIRE(fd != -1);

    // Step 3: pass it to an application and have it catch up to the generated
    // history, streaming ledgerCloseMeta to the file descriptor.
    Hash hash;
    {
        Config cfg = getTestConfig(1);
        cfg = tCfg.configure(cfg, false);
        cfg.METADATA_OUTPUT_FILE_DESCRIPTOR = fd;
        VirtualClock clock;
        auto app = createTestApplication(
            clock, cfg, /*newdb=*/true,
            Application::AppMode::REPLAY_HISTORY_FOR_METADATA);

        CatchupConfiguration cc{CatchupConfiguration::CURRENT,
                                std::numeric_limits<uint32_t>::max(),
                                CatchupConfiguration::Mode::OFFLINE_COMPLETE};
        Json::Value catchupInfo;
        auto& ham = app->getHistoryArchiveManager();
        auto& lm = app->getLedgerManager();
        auto archive = ham.selectRandomReadableHistoryArchive();
        int res = catchup(app, cc, catchupInfo, archive);
        REQUIRE(res == 0);
        hash = lm.getLastClosedLedgerHeader().hash;
        while (!lm.metadataBufferEmpty())
        {
            clock.crank(true);
        }
        while (clock.cancelAllEvents() ||
               app->getProcessManager().getNumRunningProcesses() > 0)
        {
            clock.crank(false);
        }
    }

    // Step 4: reopen the file as an XDR stream and read back the LCMs
    // and check they have the expected content.
    XDRInputFileStream stream;
    stream.open(path);
    LedgerCloseMeta lcm;
    size_t nLcm = 1;
    while (stream && stream.readOne(lcm))
    {
        ++nLcm;
    }
    // 5 checkpoints is ledger 0x13f
    REQUIRE(nLcm == 0x13f);
    REQUIRE(lcm.v0().ledgerHeader.hash == hash);
}
#endif
