// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/PathPaymentStrictReceiveOpFrame.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "ledger/TrustLineWrapper.h"
#include "transactions/PathPaymentStrictReceiveCache.h"
#include "transactions/TransactionUtils.h"
#include "util/GlobalChecks.h"
#include "util/XDROperators.h"
#include "util/Logging.h"
#include <Tracy.hpp>

namespace stellar
{

PathPaymentStrictReceiveOpFrame::PathPaymentStrictReceiveOpFrame(
    Operation const& op, OperationResult& res, TransactionFrame& parentTx)
    : PathPaymentOpFrameBase(op, res, parentTx)
    , mPathPayment(mOperation.body.pathPaymentStrictReceiveOp())
{
}

bool
PathPaymentStrictReceiveOpFrame::doApply(AbstractLedgerTxn& ltx)
{
    std::optional<PathPaymentStrictReceiveCache> ppsrc{std::nullopt};
    return doApply(ltx, ppsrc);
}

bool
PathPaymentStrictReceiveOpFrame::doApply(
    AbstractLedgerTxn& ltx, std::optional<PathPaymentStrictReceiveCache>& ppsrc)
{
    ZoneNamedN(applyZone, "PathPaymentStrictReceiveOp apply", true);
    std::string pathStr = assetToString(getSourceAsset());
    for (auto const& asset : mPathPayment.path)
    {
        pathStr += "->";
        pathStr += assetToString(asset);
    }
    pathStr += "->";
    pathStr += assetToString(getDestAsset());
    ZoneTextV(applyZone, pathStr.c_str(), pathStr.size());

    setResultSuccess();

    bool doesSourceAccountExist = true;
    if (ltx.loadHeader().current().ledgerVersion < 8)
    {
        doesSourceAccountExist =
            (bool)stellar::loadAccountWithoutRecord(ltx, getSourceID());
    }

    bool bypassIssuerCheck = shouldBypassIssuerCheck(mPathPayment.path);
    if (!bypassIssuerCheck)
    {
        if (!stellar::loadAccountWithoutRecord(ltx, getDestID()))
        {
            setResultNoDest();
            return false;
        }
    }

    if (!updateDestBalance(ltx, mPathPayment.destAmount, bypassIssuerCheck))
    {
        return false;
    }
    innerResult().success().last = SimplePaymentResult(
        getDestID(), getDestAsset(), mPathPayment.destAmount);

    // build the full path from the destination, ending with sendAsset
    std::vector<Asset> fullPath;
    fullPath.insert(fullPath.end(), mPathPayment.path.rbegin(),
                    mPathPayment.path.rend());
    fullPath.emplace_back(getSourceAsset());

    // Before each iteration of the path-loop, maxAmountRecv is the upper bound on the amount
    // of the current step's recv-side to recieve. After each iteration of the loop (including
    // the final iteration) it is updated to hold the amount of the send-side of the step that
    // just finished (which becomes the upper-bound of the recv-side of the next iteration if
    // there is one).
    int64_t maxAmountRecv;

    // We walk the path up to twice if we're going to use the cache, otherwise only once.
    bool shouldUseCache = ppsrc.has_value() && ppsrc->shouldUseCache(ltx.loadHeader().current().ledgerVersion);
    for (size_t pass = 0; pass < (shouldUseCache ? 2 : 1); ++pass)
    {
        bool passUsesCache = shouldUseCache && pass == 0;
        size_t maxOffersToCross = getMaxOffersToCross();
    
        // Walk the path
        Asset firstRecvAsset = getDestAsset();
        Asset const* recvAssetPtr = &firstRecvAsset;
        maxAmountRecv = mPathPayment.destAmount;

        for (auto sendAssetIter = fullPath.begin();
             sendAssetIter != fullPath.end(); ++sendAssetIter)
        {
            auto const& sendAsset = *sendAssetIter;
            auto const& recvAsset = *recvAssetPtr;

            if (recvAsset == sendAsset)
            {
                continue;
            }

            if (passUsesCache)
            {
                if (ltx.loadHeader().current().ledgerVersion >= 18 && maxOffersToCross == 0)
                {
                    // We don't need the cache to be valid in this case because we are
                    // only relying on information from previous cache hits.
                    mResult.code(opEXCEEDED_WORK_LIMIT);
                    ppsrc->cacheHit();
                    return false;
                }

                auto i = ppsrc->findCacheEntry(maxAmountRecv, recvAsset,
                                               firstRecvAsset, fullPath.begin(), sendAssetIter);
                if (!i.has_value())
                {
                    // This is just 'continue outer_loop', but C++ has no labeled continue.
                    goto continue_outer_loop;
                }

                PathPaymentCacheInformation const &c = (*i)->cacheInfo;
                PathPaymentStrictReceiveCache::SimulatedExchangeResult ser;
                if (!PathPaymentStrictReceiveCache::simulateExchangeWithOrderBook(c, getSourceID(), maxAmountRecv,
                                                maxOffersToCross, ser))
                {
                    // We are uncertain about the outcome of exchanging with the order
                    // book so we can't guarantee failure.
                    goto continue_outer_loop;
                }

                ser = PathPaymentStrictReceiveCache::selectExchangeResult(
                    ser, PathPaymentStrictReceiveCache::simulateExchangeWithLiquidityPool(c, maxAmountRecv));
                if (std::holds_alternative<OperationResult>(ser))
                {
                    mResult = std::get<OperationResult>(ser);
                    ppsrc->cacheHit();
                    return false;
                }

                releaseAssert(std::holds_alternative<PathPaymentStrictReceiveCache::CrossedSuccessfully>(ser));
                auto const& success = std::get<PathPaymentStrictReceiveCache::CrossedSuccessfully>(ser);
                maxAmountRecv = success.amountSend;
                maxOffersToCross -= success.numOffersCrossed;
            }
            else
            {
                if (!checkIssuer(ltx, sendAsset))
                {
                    return false;
                }

                int64_t maxOffersToCross = INT64_MAX;
                if (ltx.loadHeader().current().ledgerVersion >=
                    FIRST_PROTOCOL_SUPPORTING_OPERATION_LIMITS)
                {
                    size_t offersCrossed = innerResult().success().offers.size();
                    // offersCrossed will never be bigger than INT64_MAX because
                    // - the machine would have run out of memory
                    // - the limit, which cannot exceed INT64_MAX, should be enforced
                    // so this subtraction is safe because getMaxOffersToCross() >= 0
                    maxOffersToCross = getMaxOffersToCross() - offersCrossed;
                }

                int64_t amountSend = 0;
                int64_t amountRecv = 0;
                std::vector<ClaimAtom> offerTrail;
                auto cacheInfo = ppsrc.has_value()
                                    ? std::make_optional<PathPaymentCacheInformation>()
                                    : std::nullopt;
                auto convRes = convert(ltx, maxOffersToCross, sendAsset, INT64_MAX,
                                    amountSend, recvAsset, maxAmountRecv, amountRecv,
                                    RoundingType::PATH_PAYMENT_STRICT_RECEIVE,
                                    offerTrail, cacheInfo);

                if (ppsrc.has_value())
                {
                    ppsrc.value().insert(sendAsset, recvAsset,
                                        std::move(cacheInfo.value()));
                }

                if (!convRes)
                {
                    return false;
                }

                maxAmountRecv = amountSend;

                // add offers that got taken on the way
                // insert in front to match the path's order
                auto& offers = innerResult().success().offers;
                offers.insert(offers.begin(), offerTrail.begin(), offerTrail.end());
            }
            recvAssetPtr = &sendAsset;
        }

        if (maxAmountRecv > mPathPayment.sendMax)
        {
            if (passUsesCache)
            {
                ppsrc->cacheHit();
            }
            setResultConstraintNotMet();
            return false;
        }

        // Hack to emulate 'continue <outer_loop>', a structured-control primitive C++ lacks.
        continue_outer_loop:
            (void)0;
    }

    if (!updateSourceBalance(ltx, maxAmountRecv, bypassIssuerCheck,
                             doesSourceAccountExist))
    {
        return false;
    }
    return true;
}

bool
PathPaymentStrictReceiveOpFrame::doCheckValid(uint32_t ledgerVersion)
{
    if (mPathPayment.destAmount <= 0 || mPathPayment.sendMax <= 0)
    {
        setResultMalformed();
        return false;
    }
    if (!isAssetValid(mPathPayment.sendAsset, ledgerVersion) ||
        !isAssetValid(mPathPayment.destAsset, ledgerVersion))
    {
        setResultMalformed();
        return false;
    }
    for (auto const& p : mPathPayment.path)
    {
        if (!isAssetValid(p, ledgerVersion))
        {
            setResultMalformed();
            return false;
        }
    }
    return true;
}

bool
PathPaymentStrictReceiveOpFrame::checkTransfer(int64_t maxSend,
                                               int64_t amountSend,
                                               int64_t maxRecv,
                                               int64_t amountRecv) const
{
    return maxRecv == amountRecv;
}

Asset const&
PathPaymentStrictReceiveOpFrame::getSourceAsset() const
{
    return mPathPayment.sendAsset;
}

Asset const&
PathPaymentStrictReceiveOpFrame::getDestAsset() const
{
    return mPathPayment.destAsset;
}

MuxedAccount const&
PathPaymentStrictReceiveOpFrame::getDestMuxedAccount() const
{
    return mPathPayment.destination;
}

xdr::xvector<Asset, 5> const&
PathPaymentStrictReceiveOpFrame::getPath() const
{
    return mPathPayment.path;
}

void
PathPaymentStrictReceiveOpFrame::setResultSuccess()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_SUCCESS);
}

void
PathPaymentStrictReceiveOpFrame::setResultMalformed()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_MALFORMED);
}

void
PathPaymentStrictReceiveOpFrame::setResultUnderfunded()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_UNDERFUNDED);
}

void
PathPaymentStrictReceiveOpFrame::setResultSourceNoTrust()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_SRC_NO_TRUST);
}

void
PathPaymentStrictReceiveOpFrame::setResultSourceNotAuthorized()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_SRC_NOT_AUTHORIZED);
}

void
PathPaymentStrictReceiveOpFrame::setResultNoDest()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_NO_DESTINATION);
}

void
PathPaymentStrictReceiveOpFrame::setResultDestNoTrust()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_NO_TRUST);
}

void
PathPaymentStrictReceiveOpFrame::setResultDestNotAuthorized()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_NOT_AUTHORIZED);
}

void
PathPaymentStrictReceiveOpFrame::setResultLineFull()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_LINE_FULL);
}

void
PathPaymentStrictReceiveOpFrame::setResultNoIssuer(Asset const& asset)
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_NO_ISSUER);
    innerResult().noIssuer() = asset;
}

void
PathPaymentStrictReceiveOpFrame::setResultTooFewOffers()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_TOO_FEW_OFFERS);
}

void
PathPaymentStrictReceiveOpFrame::setResultOfferCrossSelf()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_OFFER_CROSS_SELF);
}

void
PathPaymentStrictReceiveOpFrame::setResultConstraintNotMet()
{
    innerResult().code(PATH_PAYMENT_STRICT_RECEIVE_OVER_SENDMAX);
}
}
