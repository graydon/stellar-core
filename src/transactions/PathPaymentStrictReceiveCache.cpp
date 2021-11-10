// Copyright 2021 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/PathPaymentStrictReceiveCache.h"
#include "transactions/OfferExchange.h"
#include "util/Logging.h"
#include "util/Math.h"
#include <Tracy.hpp>
#include <variant>

namespace stellar
{

PathPaymentStrictReceiveCache::PathPaymentStrictReceiveCache()
    : mIsCacheEnabled(!getenv("DISABLE_PPSRC"))
{
}

bool
PathPaymentStrictReceiveCache::isInvalid(Asset const& sendAsset,
                                         Asset const& recvAsset) const
{
    for (auto j = mInvalidatedByThisTx.begin(); j != mInvalidatedByThisTx.end();
         ++j)
    {
        if (j->first == sendAsset && j->second == recvAsset)
        {
            return true;
        }
    }
    return false;
}

static void
setInner(OperationResult& res, PathPaymentStrictReceiveResultCode code)
{
    res.tr().pathPaymentStrictReceiveResult().code(code);
}

static PathPaymentStrictReceiveCache::SimulatedExchangeResult
makeResult(OperationResultCode c)
{
    return PathPaymentStrictReceiveCache::SimulatedExchangeResult(OperationResult(c));
}

static PathPaymentStrictReceiveCache::SimulatedExchangeResult
makeResult(PathPaymentStrictReceiveResultCode c)
{
    OperationResult res(opINNER);
    res.tr().type(PATH_PAYMENT_STRICT_RECEIVE);
    setInner(res, c);
    return PathPaymentStrictReceiveCache::SimulatedExchangeResult(std::move(res));
}

std::optional<PathPaymentStrictReceiveCache::CrossedSuccessfully>
PathPaymentStrictReceiveCache::simulateExchangeWithLiquidityPool(PathPaymentCacheInformation const& c,
                                  int64_t destAmount)
{
    std::optional<CrossedSuccessfully> res;
    if (c.liquidityPool)
    {
        auto const& lp = *c.liquidityPool;
        int64_t toPool = 0;
        int64_t fromPool = 0;
        if (exchangeWithPool(lp.reserveSend, INT64_MAX, toPool,
                             lp.reserveReceive, destAmount, fromPool, 30,
                             RoundingType::PATH_PAYMENT_STRICT_RECEIVE))
        {
            res = std::make_optional<CrossedSuccessfully>();
            res->amountSend = toPool;
            res->numOffersCrossed = 1;
        }
    }
    return res;
}

// Returns true if we have a guaranteed result and false otherwise
bool
PathPaymentStrictReceiveCache::simulateExchangeWithOrderBook(PathPaymentCacheInformation const& c,
                              AccountID const& sourceID, int64_t destAmount,
                              int64_t maxOffersToCross,
                              SimulatedExchangeResult& ser)
{
    ser.emplace<CrossedSuccessfully>();
    auto& success = std::get<CrossedSuccessfully>(ser);

    bool crossSelf =
        std::find(c.sellerIDsBeforeLast.begin(), c.sellerIDsBeforeLast.end(),
                  sourceID) != c.sellerIDsBeforeLast.end();

    success.numOffersCrossed = c.numOffersCrossedBeforeLast;
    if (success.numOffersCrossed > maxOffersToCross)
    {
        if (crossSelf)
        {
            // We've already crossed too many offers and one of those was a
            // self-cross, but we don't know if it was before or after we
            // hit the limit.
            //
            // In theory, we could go look for a more relevant cache entry.
            return false;
        }
        ser = makeResult(opEXCEEDED_WORK_LIMIT);
        return true;
    }
    else if (crossSelf)
    {
        // One of the completely crossed offers was a self-trade
        ser = makeResult(PATH_PAYMENT_STRICT_RECEIVE_OFFER_CROSS_SELF);
        return true;
    }

    if (c.amountReceiveBeforeLast == destAmount)
    {
        // This is exactly the amount desired, so we don't need to try
        // crossing the next offer
        success.amountSend = c.amountSendBeforeLast;
    }
    else if (c.lastCross)
    {
        // This is less than the amount desired, so try crossing the next
        // offer
        auto const& o = *c.lastCross;
        if (o.sellerID == sourceID)
        {
            // This is a self-trade
            ser = makeResult(PATH_PAYMENT_STRICT_RECEIVE_OFFER_CROSS_SELF);
            return true;
        }

        ++success.numOffersCrossed;
        if (success.numOffersCrossed >= maxOffersToCross)
        {
            // Crossing this offer will exceed the limit
            ser = makeResult(opEXCEEDED_WORK_LIMIT);
            return true;
        }

        int64_t maxWheatReceived = destAmount - c.amountReceiveBeforeLast;
        int64_t maxSheepSend = INT64_MAX - c.amountSendBeforeLast;
        auto res = exchangeV10(o.price, o.maxWheatSend, maxWheatReceived,
                               maxSheepSend, o.maxSheepReceive,
                               RoundingType::PATH_PAYMENT_STRICT_RECEIVE);

        if (res.numWheatReceived < maxWheatReceived)
        {
            // If wheatStays and we didn't receive enough, then the
            // operation must fail because it won't be able to cross another
            // offer. If areNoRemainingOffers and we didn't receive enough,
            // then the operation must fail because there are no more offers
            // to cross.
            if (res.wheatStays || c.areNoRemainingOffers)
            {
                ser = makeResult(PATH_PAYMENT_STRICT_RECEIVE_TOO_FEW_OFFERS);
                return true;
            }
            // We don't know about the next offers to be crossed, so we
            // can't guarantee failure.
            return false;
        }

        success.amountSend = c.amountSendBeforeLast + res.numSheepSend;
    }
    else
    {
        // No offers
        ser = makeResult(PATH_PAYMENT_STRICT_RECEIVE_TOO_FEW_OFFERS);
        return true;
    }

    return true;
}

PathPaymentStrictReceiveCache::SimulatedExchangeResult
PathPaymentStrictReceiveCache::selectExchangeResult(SimulatedExchangeResult const& ob,
                     std::optional<CrossedSuccessfully> const& lp)
{
    if (!lp)
    {
        return ob;
    }
    else if (std::holds_alternative<CrossedSuccessfully>(ob))
    {
        auto const& obSuccess = std::get<CrossedSuccessfully>(ob);
        return lp->amountSend <= obSuccess.amountSend
                   ? PathPaymentStrictReceiveCache::SimulatedExchangeResult(*lp)
                   : ob;
    }
    else // if (std::holds_alternative<OperationResult>(ob))
    {
        return PathPaymentStrictReceiveCache::SimulatedExchangeResult(*lp);
    }
}

bool
PathPaymentStrictReceiveCache::isDuplicateExchange(Asset const& firstRecvAsset,
                    std::vector<Asset>::const_iterator begin,
                    std::vector<Asset>::const_iterator sendIter)
{
    if (begin == sendIter)
    {
        return false;
    }

    auto const& recvAsset = *(sendIter - 1);
    auto const& sendAsset = *sendIter;

    if (recvAsset == firstRecvAsset && sendAsset == *begin)
    {
        return true;
    }

    for (auto s = begin + 1; s != sendIter; ++s)
    {
        auto r = s - 1;
        if (recvAsset == *r && sendAsset == *s)
        {
            return true;
        }
    }
    return false;
}

bool
PathPaymentStrictReceiveCache::shouldUseCache(uint32_t ledgerVersion)
{
    ++mNumQueries;
    if (!mIsCacheEnabled)
    {
        return false;
    }

    if (ledgerVersion < 13)
    {
        // Before protocol version 10 we used a different rounding algorithm
        // From protocol version 10 to 13 we also checked issuers
        return false;
    }
    return true;
}


std::optional<std::vector<PathPaymentStrictReceiveCache::CrossedOffersInformation>::const_iterator>
PathPaymentStrictReceiveCache::findCacheEntry(int64_t destAmount, Asset const& recvAsset, Asset const& firstRecvAsset,
                    std::vector<Asset>::const_iterator begin,
                    std::vector<Asset>::const_iterator sendIter) const
{
    auto const& sendAsset = *sendIter;

    if (isInvalid(sendAsset, recvAsset) ||
        isDuplicateExchange(firstRecvAsset, begin, sendIter))
    {
        return std::nullopt;
    }

    std::vector<CrossedOffersInformation>::const_iterator i = mCache.end();
    for (auto j = mCache.begin(); j != mCache.end(); ++j)
    {
        if (j->cacheInfo.amountReceiveBeforeLast <= destAmount &&
            (i == mCache.end() ||
                i->cacheInfo.amountReceiveBeforeLast <
                    j->cacheInfo.amountReceiveBeforeLast) &&
            j->sendAsset == sendAsset && j->recvAsset == recvAsset)
        {
            i = j;
        }
    }
    return i == mCache.end() ? std::nullopt : std::make_optional(i);
}

bool
PathPaymentStrictReceiveCache::isGuaranteedToFail(
    uint32_t ledgerVersion, AccountID const& sourceID, int64_t destAmount,
    int64_t sendMax, Asset const& firstRecvAsset,
    std::vector<Asset> const& sendAssets, int64_t maxOffersToCross,
    OperationResult& result) const
{
    ZoneScoped;
    ++mNumQueries;

    if (!mIsCacheEnabled)
    {
        return false;
    }

    if (ledgerVersion < 13)
    {
        // Before protocol version 10 we used a different rounding algorithm
        // From protocol version 10 to 13 we also checked issuers
        return false;
    }

    Asset const* recvAssetPtr = &firstRecvAsset;
    for (auto sendAssetIter = sendAssets.begin();
         sendAssetIter != sendAssets.end(); ++sendAssetIter)
    {
        auto const& sendAsset = *sendAssetIter;
        if (*recvAssetPtr == sendAsset)
        {
            continue;
        }

        if (ledgerVersion >= 18 && maxOffersToCross == 0)
        {
            // We don't need the cache to be valid in this case because we are
            // only relying on information from previous cache hits.
            result.code(opEXCEEDED_WORK_LIMIT);
            ++mNumGuaranteedToFail;
            return true;
        }

        if (isInvalid(sendAsset, *recvAssetPtr))
        {
            return false;
        }

        // Check that this isn't a duplicate of an earlier pair, otherwise the
        // cache won't reflect the fact that trades have already happened
        if (isDuplicateExchange(firstRecvAsset, sendAssets.begin(),
                                sendAssetIter))
        {
            return false;
        }

        std::vector<CrossedOffersInformation>::const_iterator i = mCache.end();
        for (auto j = mCache.begin(); j != mCache.end(); ++j)
        {
            if (j->cacheInfo.amountReceiveBeforeLast <= destAmount &&
                (i == mCache.end() ||
                 i->cacheInfo.amountReceiveBeforeLast <
                     j->cacheInfo.amountReceiveBeforeLast) &&
                j->sendAsset == sendAsset && j->recvAsset == *recvAssetPtr)
            {
                i = j;
            }
        }

        if (i == mCache.end())
        {
            return false;
        }
        auto const& c = i->cacheInfo;

        SimulatedExchangeResult ser;
        if (!simulateExchangeWithOrderBook(c, sourceID, destAmount,
                                           maxOffersToCross, ser))
        {
            // We are uncertain about the outcome of exchanging with the order
            // book so we can't guarantee failure.
            return false;
        }

        ser = selectExchangeResult(
            ser, simulateExchangeWithLiquidityPool(c, destAmount));
        if (std::holds_alternative<OperationResult>(ser))
        {
            result = std::get<OperationResult>(ser);
            ++mNumGuaranteedToFail;
            return true;
        }
        else // if (std::holds_alternative<CrossedSuccessfully>(ser))
        {
            auto const& success = std::get<CrossedSuccessfully>(ser);
            destAmount = success.amountSend;
            maxOffersToCross -= success.numOffersCrossed;
        }

        recvAssetPtr = &sendAsset;
    }

    if (destAmount > sendMax)
    {
        // We were able to process the whole path but we had to send too much
        setInner(result, PATH_PAYMENT_STRICT_RECEIVE_OVER_SENDMAX);
        ++mNumGuaranteedToFail;
        return true;
    }

    return false;
}

void
PathPaymentStrictReceiveCache::insert(Asset const& sendAsset,
                                      Asset const& recvAsset,
                                      PathPaymentCacheInformation&& cacheInfo)
{
    ZoneScoped;

    invalidate(sendAsset, recvAsset);

    CrossedOffersInformation coi{recvAsset, sendAsset, std::move(cacheInfo)};
    if (mCache.size() >= mMaxCacheEntries)
    {
        rand_element(mCache) = std::move(coi);
    }
    else
    {
        mCache.emplace_back(std::move(coi));
    }
}

void
PathPaymentStrictReceiveCache::invalidate(Asset const& sendAsset,
                                          Asset const& recvAsset)
{
    if (isInvalid(sendAsset, recvAsset))
    {
        return;
    }
    mInvalidatedByThisTx.emplace_back(sendAsset, recvAsset);
}

void
PathPaymentStrictReceiveCache::transactionFailed()
{
    mInvalidatedByThisTx.clear();
}

void
PathPaymentStrictReceiveCache::transactionSuccessful()
{
    size_t n = mCache.size();
    for (size_t i = 0; i < n;)
    {
        if (isInvalid(mCache[i].sendAsset, mCache[i].recvAsset))
        {
            --n;
            std::swap(mCache[i], mCache[n]);
        }
        else
        {
            ++i;
        }
    }
    mCache.resize(n);

    mInvalidatedByThisTx.clear();
}

void
PathPaymentStrictReceiveCache::cacheHit()
{
    ++mNumGuaranteedToFail;
}

void
PathPaymentStrictReceiveCache::log()
{
    CLOG_ERROR(Tx,
               "{} / {} PathPaymentStrictReceiveOperations guaranteed to fail",
               mNumGuaranteedToFail, mNumQueries);
    mNumGuaranteedToFail = 0;
    mNumQueries = 0;
}
}
