// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "historywork/BatchDownloadWork.h"
#include "catchup/CatchupManager.h"
#include "history/HistoryManager.h"
#include "historywork/GetAndUnzipRemoteFileWork.h"
#include "historywork/Progress.h"
#include "lib/util/format.h"
#include "main/Application.h"
#include <medida/meter.h>
#include <medida/metrics_registry.h>

namespace stellar
{
BatchDownloadWork::BatchDownloadWork(Application& app, CheckpointRange range,
                                     std::string const& type,
                                     TmpDir const& downloadDir)
    : BatchWork(app, fmt::format("batch-download-{:s}-{:08x}-{:08x}", type,
                                 range.first(), range.last()))
    , mRange(range)
    , mNext(range.first())
    , mFileType(type)
    , mDownloadDir(downloadDir)
{
}

std::string
BatchDownloadWork::getStatus() const
{
    if (getState() == State::WORK_RUNNING)
    {
        auto task = fmt::format("downloading {:s} files", mFileType);
        return fmtProgress(mApp, task, mRange.first(), mRange.last(), mNext);
    }
    return BatchWork::getStatus();
}

std::shared_ptr<BasicWork>
BatchDownloadWork::yieldMoreWork()
{
    if (!hasNext())
    {
        CLOG(WARNING, "Work")
            << getName() << " has no more children to iterate over! ";
        return nullptr;
    }

    FileTransferInfo ft(mDownloadDir, mFileType, mNext);
    CLOG(DEBUG, "History") << "Downloading and unzipping " << mFileType
                           << " for checkpoint " << mNext;
    // TODO (mlo) It's better to have BatchWork actually add work
    auto getAndUnzip = addWork<GetAndUnzipRemoteFileWork>(ft);
    mApp.getCatchupManager().logAndUpdateCatchupStatus(true);
    mNext += mApp.getHistoryManager().getCheckpointFrequency();

    return getAndUnzip;
}

bool
BatchDownloadWork::hasNext() const
{
    return mNext <= mRange.last();
}

void
BatchDownloadWork::resetIter()
{
    mNext = mRange.first();
}
}
