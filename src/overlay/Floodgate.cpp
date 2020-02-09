// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "overlay/Floodgate.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "herder/Herder.h"
#include "main/Application.h"
#include "medida/counter.h"
#include "medida/metrics_registry.h"
#include "overlay/OverlayManager.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"

namespace stellar
{
Floodgate::FloodRecord::FloodRecord(StellarMessage const& msg, uint32_t ledger,
                                    Peer::pointer peer)
    : mLedgerSeq(ledger), mMessage(std::make_unique<StellarMessage>(msg))
{
    if (peer)
        mPeersTold.insert(peer->toString());
}
Floodgate::FloodRecord::FloodRecord(uint32_t ledger, Peer::pointer peer)
    : mLedgerSeq(ledger), mMessage(nullptr)
{
    if (peer)
        mPeersTold.insert(peer->toString());
}

Floodgate::Floodgate(Application& app)
    : mApp(app)
    , mFloodMapSize(
          app.getMetrics().NewCounter({"overlay", "memory", "flood-known"}))
    , mSendFromBroadcast(app.getMetrics().NewMeter(
          {"overlay", "flood", "broadcast"}, "message"))
    , mMessagesAdvertized(app.getMetrics().NewMeter(
          {"overlay", "flood", "advertized"}, "message"))
    , mMessagesDemanded(app.getMetrics().NewMeter(
          {"overlay", "flood", "demanded"}, "message"))
    , mMessagesFulfilled(app.getMetrics().NewMeter(
          {"overlay", "flood", "fulfilled"}, "message"))
    , mShuttingDown(false)
{
    mId = KeyUtils::toShortString(mApp.getConfig().NODE_SEED.getPublicKey());
}

// remove old flood records
void
Floodgate::clearBelow(uint32_t currentLedger)
{
    for (auto it = mFloodMap.cbegin(); it != mFloodMap.cend();)
    {
        // give ten ledgers of leeway
        if (it->second->mLedgerSeq + 10 < currentLedger)
        {
            mPendingDemanded.erase(it->first);
            it = mFloodMap.erase(it);
        }
        else
        {
            ++it;
        }
    }
    mFloodMapSize.set_count(mFloodMap.size());
}

bool
Floodgate::addRecord(StellarMessage const& msg, Peer::pointer peer, Hash& index)
{
    index = sha256(xdr::xdr_to_opaque(msg));
    if (mShuttingDown)
    {
        return false;
    }
    mPendingDemanded.erase(index);
    auto result = mFloodMap.find(index);
    if (result == mFloodMap.end())
    { // we have never seen this message
        mFloodMap[index] = std::make_shared<FloodRecord>(
            msg, mApp.getHerder().getCurrentLedgerSeq(), peer);
        mFloodMapSize.set_count(mFloodMap.size());
        return true;
    }
    else
    {
        if (!result->second->mMessage)
        {
            // We're receiving the actual message for one we only
            // knew about, but didn't have yet.
            CLOG(TRACE, "Overlay")
                << mId << " upgrading " << hexAbbrev(index)
                << " from only-known to actually-have (in addRecord)";
            result->second->mMessage = std::make_unique<StellarMessage>(msg);
            return true;
        }
        result->second->mPeersTold.insert(peer->toString());
        return false;
    }
}

// send message to anyone you haven't gotten it from
void
Floodgate::broadcast(StellarMessage const& msg, bool force,
                     uint32_t minOverlayVersion)
{
    if (mShuttingDown)
    {
        return;
    }
    Hash index = sha256(xdr::xdr_to_opaque(msg));
    CLOG(TRACE, "Overlay") << "broadcast " << hexAbbrev(index);

    mPendingDemanded.erase(index);
    auto result = mFloodMap.find(index);
    if (result == mFloodMap.end() || force)
    { // no one has sent us this message
        FloodRecord::pointer record = std::make_shared<FloodRecord>(
            msg, mApp.getHerder().getCurrentLedgerSeq(), Peer::pointer());
        result = mFloodMap.insert(std::make_pair(index, record)).first;
        mFloodMapSize.set_count(mFloodMap.size());
    }
    else if (result != mFloodMap.end() && !result->second->mMessage)
    {
        // We're receiving the actual message for one we only
        // knew about, but didn't have yet.
        CLOG(TRACE, "Overlay")
            << mId << " upgrading " << hexAbbrev(index)
            << " from only-known to actually-have (in broadcast)";
        result->second->mMessage = std::make_unique<StellarMessage>(msg);
    }

    // send it to people that haven't sent it to us
    auto& peersTold = result->second->mPeersTold;

    // make a copy, in case peers gets modified
    auto peers = mApp.getOverlayManager().getAuthenticatedPeers();

    for (auto peer : peers)
    {
        assert(peer.second->isAuthenticated());
        if (peersTold.find(peer.second->toString()) == peersTold.end() &&
            peer.second->getRemoteOverlayVersion() >= minOverlayVersion)
        {
            if (peer.second->supportsAdverts())
            {
                CLOG(TRACE, "Overlay")
                    << mId << " advertizing " << hexAbbrev(index) << " to "
                    << KeyUtils::toShortString(peer.second->getPeerID());
                mMessagesAdvertized.Mark();
                peer.second->advertizeMessage(index);
            }
            else
            {
                mSendFromBroadcast.Mark();
                peer.second->sendMessage(msg);
                peersTold.insert(peer.second->toString());
            }
        }
    }
    CLOG(TRACE, "Overlay") << "broadcast " << hexAbbrev(index) << " told "
                           << peersTold.size();
}

void
Floodgate::demandMissing(FloodAdvert const& adv, Peer::pointer fromPeer)
{
    StellarMessage msg;
    msg.type(FLOOD_DEMAND);
    FloodDemand& demand = msg.floodDemand();
    for (Hash const& h : adv.hashes)
    {
        auto i = mFloodMap.find(h);
        bool haveMessage = false;
        // Add to floodMap so it can be found by item-fetching.
        if (i == mFloodMap.end())
        {
            CLOG(TRACE, "Overlay")
                << mId << " marking message " << hexAbbrev(h)
                << " advertized by "
                << KeyUtils::toShortString(fromPeer->getPeerID())
                << " known (but don't have it)";
            mFloodMap[h] = std::make_shared<FloodRecord>(
                mApp.getHerder().getCurrentLedgerSeq(), fromPeer);
            mFloodMapSize.set_count(mFloodMap.size());
        }
        else
        {
            i->second->mPeersTold.insert(fromPeer->toString());
            haveMessage = static_cast<bool>(i->second->mMessage);
            if (haveMessage)
            {
                CLOG(TRACE, "Overlay")
                    << mId << " know of message " << hexAbbrev(h)
                    << " advertized by "
                    << KeyUtils::toShortString(fromPeer->getPeerID())
                    << " and already have it";
            }
            else
            {
                CLOG(TRACE, "Overlay")
                    << mId << " know of message " << hexAbbrev(h)
                    << " advertized by "
                    << KeyUtils::toShortString(fromPeer->getPeerID())
                    << " and don't have it";
            }
        }
        if (mPendingDemanded.find(h) != mPendingDemanded.end())
        {
            CLOG(TRACE, "Overlay")
                << mId << " already demanded " << hexAbbrev(h)
                << " advertized by "
                << KeyUtils::toShortString(fromPeer->getPeerID());
        }
        if (!haveMessage && mPendingDemanded.find(h) == mPendingDemanded.end())
        {
            CLOG(TRACE, "Overlay")
                << mId << " demanding " << hexAbbrev(h) << " from "
                << KeyUtils::toShortString(fromPeer->getPeerID());
            // We don't have this message in full and haven't
            // demanded it yet from anyone who advertized it; ask
            // now and leave a record that we've done so to avoid
            // demanding it from others.
            mMessagesDemanded.Mark();
            mPendingDemanded.insert(h);
            demand.hashes.emplace_back(h);
        }
    }
    fromPeer->sendMessage(msg);
}

void
Floodgate::fulfillDemand(FloodDemand const& dmd, Peer::pointer fromPeer)
{
    for (Hash const& h : dmd.hashes)
    {
        auto i = mFloodMap.find(h);
        if (i != mFloodMap.end())
        {
            if (i->second->mMessage)
            {
                CLOG(TRACE, "Overlay")
                    << mId << " fulfilling demand for " << hexAbbrev(h)
                    << " demanded by "
                    << KeyUtils::toShortString(fromPeer->getPeerID());
                mMessagesFulfilled.Mark();
                fromPeer->sendMessage(*(i->second->mMessage));
            }
            else
            {
                CLOG(TRACE, "Overlay")
                    << mId << " can't fulfill demand for " << hexAbbrev(h)
                    << " demanded by "
                    << KeyUtils::toShortString(fromPeer->getPeerID())
                    << " -- know of message but don't have it";
            }
        }
        else
        {
            CLOG(TRACE, "Overlay")
                << mId << " can't fulfill demand for " << hexAbbrev(h)
                << " demanded by "
                << KeyUtils::toShortString(fromPeer->getPeerID())
                << " -- don't know of message";
        }
    }
}

std::set<Peer::pointer>
Floodgate::getPeersKnows(Hash const& h)
{
    std::set<Peer::pointer> res;
    auto record = mFloodMap.find(h);
    if (record != mFloodMap.end())
    {
        auto& ids = record->second->mPeersTold;
        auto const& peers = mApp.getOverlayManager().getAuthenticatedPeers();
        for (auto& p : peers)
        {
            if (ids.find(p.second->toString()) != ids.end())
            {
                res.insert(p.second);
            }
        }
    }
    return res;
}

void
Floodgate::shutdown()
{
    mShuttingDown = true;
    mFloodMap.clear();
}

void
Floodgate::forgetRecord(Hash const& h)
{
    CLOG(TRACE, "Overlay") << mId << " forgetting " << hexAbbrev(h);
    mFloodMap.erase(h);
    mPendingDemanded.erase(h);
}
}
