// Copyright 2016 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "Tracker.h"

#include "OverlayMetrics.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "herder/Herder.h"
#include "main/Application.h"
#include "medida/medida.h"
#include "overlay/OverlayManager.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"

namespace stellar
{

static std::chrono::milliseconds const MS_TO_WAIT_FOR_FETCH_REPLY{1500};
static int const MAX_REBUILD_FETCH_LIST = 10;

Tracker::Tracker(Application& app, Hash const& hash, AskPeer& askPeer)
    : mAskPeer(askPeer)
    , mApp(app)
    , mNumListRebuild(0)
    , mTimer(app)
    , mItemHash(hash)
    , mTryNextPeer(
          app.getOverlayManager().getOverlayMetrics().mItemFetcherNextPeer)
    , mFetchTime("fetch-" + hexAbbrev(hash), LogSlowExecution::Mode::MANUAL)
{
    assert(mAskPeer);
}

Tracker::~Tracker()
{
    cancel();
}

SCPEnvelope
Tracker::pop()
{
    auto env = mWaitingEnvelopes.back().second;
    mWaitingEnvelopes.pop_back();
    return env;
}

// returns false if no one cares about this guy anymore
bool
Tracker::clearEnvelopesBelow(uint64 slotIndex)
{
    for (auto iter = mWaitingEnvelopes.begin();
         iter != mWaitingEnvelopes.end();)
    {
        if (iter->second.statement.slotIndex < slotIndex)
        {
            iter = mWaitingEnvelopes.erase(iter);
        }
        else
        {
            iter++;
        }
    }
    if (!mWaitingEnvelopes.empty())
    {
        return true;
    }

    mTimer.cancel();
    mLastAskedPeer = nullptr;

    return false;
}

void
Tracker::doesntHave(Peer::pointer peer)
{
    if (mLastAskedPeer == peer)
    {
        CLOG(TRACE, "Overlay") << "Does not have " << hexAbbrev(mItemHash);
        tryNextPeer();
    }
}

void
Tracker::tryNextPeer()
{
    // will be called by some timer or when we get a
    // response saying they don't have it
    CLOG(TRACE, "Overlay") << "tryNextPeer " << hexAbbrev(mItemHash)
                           << " last: "
                           << (mLastAskedPeer ? mLastAskedPeer->toString()
                                              : "<none>");

    if (mLastAskedPeer)
    {
        mTryNextPeer.Mark();
        mLastAskedPeer.reset();
    }

    // helper function to populate "candidates" with the lowest latency group
    std::vector<Peer::pointer> candidates;
    int64 curBest = INT64_MAX;
    auto procPeers = [&](std::map<NodeID, Peer::pointer> const& peerMap) {
        for (auto& mp : peerMap)
        {
            auto& p = mp.second;
            if (p->isAuthenticated() &&
                mPeersAsked.find(p) == mPeersAsked.end())
            {
                constexpr int64 GROUPSIZE_MS = 500;
                int64 plat = p->getPing().count() / GROUPSIZE_MS;
                if (plat < curBest)
                {
                    candidates.clear();
                    curBest = plat;
                    candidates.emplace_back(p);
                }
                else if (curBest == plat)
                {
                    candidates.emplace_back(p);
                }
            }
        }
    };

    // build the set of peers we didn't ask yet that have this envelope
    std::map<NodeID, Peer::pointer> newPeersWithEnvelope;
    for (auto const& e : mWaitingEnvelopes)
    {
        auto const& s = mApp.getOverlayManager().getPeersKnows(e.first);
        for (auto pit = s.begin(); pit != s.end(); ++pit)
        {
            auto& p = *pit;
            if (p->isAuthenticated() &&
                mPeersAsked.find(p) == mPeersAsked.end())
            {
                newPeersWithEnvelope.emplace(p->getPeerID(), *pit);
            }
        }
    }

    if (!newPeersWithEnvelope.empty())
    {
        procPeers(newPeersWithEnvelope);
    }
    else
    {
        auto& inPeers = mApp.getOverlayManager().getInboundAuthenticatedPeers();
        auto& outPeers =
            mApp.getOverlayManager().getOutboundAuthenticatedPeers();
        procPeers(inPeers);
        procPeers(outPeers);
    }

    // pick a random element from the candidate list
    if (!candidates.empty())
    {
        mLastAskedPeer = rand_element(candidates);
    }

    std::chrono::milliseconds nextTry;
    if (!mLastAskedPeer)
    {
        // we have asked all our peers, reset the list and try again after a
        // pause
        mNumListRebuild++;
        mPeersAsked.clear();

        CLOG(TRACE, "Overlay") << "tryNextPeer " << hexAbbrev(mItemHash)
                               << " restarting fetch #" << mNumListRebuild;

        nextTry = MS_TO_WAIT_FOR_FETCH_REPLY *
                  std::min(MAX_REBUILD_FETCH_LIST, mNumListRebuild);
    }
    else
    {
        mPeersAsked.emplace(mLastAskedPeer);
        CLOG(TRACE, "Overlay") << "Asking for " << hexAbbrev(mItemHash)
                               << " to " << mLastAskedPeer->toString();
        mAskPeer(mLastAskedPeer, mItemHash);
        nextTry = MS_TO_WAIT_FOR_FETCH_REPLY;
    }

    mTimer.expires_from_now(nextTry);
    mTimer.async_wait([this]() { this->tryNextPeer(); },
                      VirtualTimer::onFailureNoop);
}

void
Tracker::listen(const SCPEnvelope& env)
{
    mLastSeenSlotIndex = std::max(env.statement.slotIndex, mLastSeenSlotIndex);

    StellarMessage m;
    m.type(SCP_MESSAGE);
    m.envelope() = env;

    // NB: hash here is of StellarMessage
    mWaitingEnvelopes.push_back(
        std::make_pair(sha256(xdr::xdr_to_opaque(m)), env));
}

void
Tracker::discard(const SCPEnvelope& env)
{
    auto matchEnvelope = [&env](std::pair<Hash, SCPEnvelope> const& x) {
        return x.second == env;
    };
    mWaitingEnvelopes.erase(std::remove_if(std::begin(mWaitingEnvelopes),
                                           std::end(mWaitingEnvelopes),
                                           matchEnvelope),
                            std::end(mWaitingEnvelopes));
}

void
Tracker::cancel()
{
    mTimer.cancel();
    mLastSeenSlotIndex = 0;
}

std::chrono::milliseconds
Tracker::getDuration()
{
    return mFetchTime.checkElapsedTime();
}
}
