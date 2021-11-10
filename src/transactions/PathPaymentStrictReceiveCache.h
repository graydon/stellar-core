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
#include <variant>
#include <unordered_map>
#include <unordered_set>

namespace stellar
{

class PathPaymentStrictReceiveCache
{
  public:

    struct CrossedOffersInformation
    {
        Asset recvAsset;
        Asset sendAsset;
        // TODO: merge PathPaymentCacheInformation and CrossedOffersInformation
        PathPaymentCacheInformation cacheInfo;
    };

    struct CrossedSuccessfully
    {
      int64_t amountSend{0};
      int64_t numOffersCrossed{0};
    };

    typedef std::variant<CrossedSuccessfully, OperationResult>
      SimulatedExchangeResult;

  private:

    bool mIsCacheEnabled;
    std::vector<CrossedOffersInformation> mCache;
    mutable size_t mNumGuaranteedToFail{0};
    mutable size_t mNumQueries{0};
    size_t mMaxCacheEntries{64};

    std::vector<std::pair<Asset, Asset>> mInvalidatedByThisTx;
    bool isInvalid(Asset const& sendAsset, Asset const& recvAsset) const;

  public:

    PathPaymentStrictReceiveCache();

    static SimulatedExchangeResult
    selectExchangeResult(SimulatedExchangeResult const& ob,
                         std::optional<CrossedSuccessfully> const& lp);
    
    static bool simulateExchangeWithOrderBook(PathPaymentCacheInformation const& c,
                              AccountID const& sourceID, int64_t destAmount,
                              int64_t maxOffersToCross,
                              SimulatedExchangeResult& ser);
    
    static std::optional<CrossedSuccessfully>
    simulateExchangeWithLiquidityPool(PathPaymentCacheInformation const& c,
                                  int64_t destAmount);

    bool shouldUseCache(uint32_t ledgerVersion);

    std::optional<std::vector<CrossedOffersInformation>::const_iterator>
    findCacheEntry(int64_t destAmount, Asset const& recvAsset, Asset const& firstRecvAsset,
                    std::vector<Asset>::const_iterator begin,
                    std::vector<Asset>::const_iterator sendIter) const;


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

    void cacheHit();
    void log();
};
}
