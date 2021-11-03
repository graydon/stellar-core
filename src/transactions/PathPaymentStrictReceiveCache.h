// Copyright 2021 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "ledger/LedgerHashUtils.h"
#include "overlay/StellarXDR.h"
#include "transactions/OfferExchange.h"
#include "util/XDROperators.h"
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace stellar
{

class PathPaymentStrictReceiveCache
{
  private:
    struct CrossedOffersInformation
    {
        Asset recvAsset;
        Asset sendAsset;
        PathPaymentCacheInformation cacheInfo;
    };

    bool mIsCacheEnabled;
    std::vector<CrossedOffersInformation> mCache;
    mutable size_t mNumGuaranteedToFail{0};
    mutable size_t mNumQueries{0};
    size_t mMaxCacheEntries{64};

    std::vector<std::pair<Asset, Asset>> mInvalidatedByThisTx;

    bool isInvalid(Asset const& sendAsset, Asset const& recvAsset) const;

  public:
    PathPaymentStrictReceiveCache();

    bool isGuaranteedToFail(uint32_t ledgerVersion, AccountID const& sourceID,
                            int64_t destAmount, int64_t sendMax,
                            Asset const& firstRecvAsset,
                            std::vector<Asset> const& sendAssets,
                            int64_t maxOffersToCross,
                            OperationResult& result) const;

    void insert(Asset const& sendAsset, Asset const& recvAsset,
                PathPaymentCacheInformation&& cacheInfo);

    void invalidate(Asset const& sendAsset, Asset const& recvAsset);

    void transactionFailed();

    void transactionSuccessful();

    void log();
};
}
