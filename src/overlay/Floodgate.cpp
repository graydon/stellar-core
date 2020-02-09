// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "overlay/Floodgate.h"
#include "crypto/BLAKE2.h"
#include "crypto/Hex.h"
#include "herder/Herder.h"
#include "main/Application.h"
#include "medida/counter.h"
#include "medida/metrics_registry.h"
#include "overlay/OverlayManager.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"
#include <Tracy.hpp>
#include <fmt/format.h>

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
Floodgate::clearBelow(uint32_t maxLedger)
{
    ZoneScoped;
    for (auto it = mFloodMap.cbegin(); it != mFloodMap.cend();)
    {
        if (it->second->mLedgerSeq < maxLedger)
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
    ZoneScoped;
    index = xdrBlake2(msg);
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
        TracyPlot("overlay.memory.flood-known",
                  static_cast<int64_t>(mFloodMap.size()));
        return true;
    }
    else
    {
        if (!result->second->mMessage)
        {
            // We're receiving the actual message for one we only
            // knew about, but didn't have yet.
            CLOG_TRACE(Overlay,
                       "{} upgrading {} from only-known to actually-have (in "
                       "addRecord)",
                       mId, hexAbbrev(index));
            result->second->mMessage = std::make_unique<StellarMessage>(msg);
            return true;
        }
        result->second->mPeersTold.insert(peer->toString());
        return false;
    }
}

// send message to anyone you haven't gotten it from
bool
Floodgate::broadcast(StellarMessage const& msg, bool force)
{
    ZoneScoped;
    if (mShuttingDown)
    {
        return false;
    }
    Hash index = xdrBlake2(msg);

    // If we're sending something now, we certainly shouldn't
    // demand it from anyone in the near future.
    mPendingDemanded.erase(index);

    FloodRecord::pointer fr;
    auto result = mFloodMap.find(index);
    if (result == mFloodMap.end() || force)
    { // no one has sent us this message / start from scratch
        fr = std::make_shared<FloodRecord>(
            msg, mApp.getHerder().getCurrentLedgerSeq(), Peer::pointer());
        mFloodMap[index] = fr;
        mFloodMapSize.set_count(mFloodMap.size());
    }
    else
    {
        fr = result->second;
        if (!fr->mMessage)
        {
            // We're sending the actual message for one we only
            // knew about, but didn't have yet.
            CLOG_TRACE(Overlay,
                       "{} upgrading {} from only-known to actually-have (in "
                       "broadcast)",
                       mId, hexAbbrev(index));
            fr->mMessage = std::make_unique<StellarMessage>(msg);
        }
    }
    // send it to people that haven't sent it to us
    auto& peersTold = fr->mPeersTold;

    // make a copy, in case peers gets modified
    auto peers = mApp.getOverlayManager().getAuthenticatedPeers();

    bool broadcasted = false;
    std::shared_ptr<StellarMessage> smsg =
        std::make_shared<StellarMessage>(msg);
    for (auto peer : peers)
    {
        assert(peer.second->isAuthenticated());
        if (peersTold.insert(peer.second->toString()).second)
        {
            std::weak_ptr<Peer> weak(
                std::static_pointer_cast<Peer>(peer.second));
            if (peer.second->supportsAdverts())
            {
                CLOG_TRACE(Overlay, "{} advertizing {} to {}", mId,
                           hexAbbrev(index),
                           KeyUtils::toShortString(peer.second->getPeerID()));
                mMessagesAdvertized.Mark();
                mApp.postOnMainThread(
                    [index, weak]() {
                        auto strong = weak.lock();
                        if (strong)
                        {
                            strong->advertizeMessage(index);
                        }
                    },
                    fmt::format("advertize to {}", peer.second->toString()));
            }
            else
            {
                mSendFromBroadcast.Mark();
                mApp.postOnMainThread(
                    [smsg, weak, log = !broadcasted]() {
                        auto strong = weak.lock();
                        if (strong)
                        {
                            strong->sendMessage(*smsg, log);
                        }
                    },
                    fmt::format("broadcast to {}", peer.second->toString()));
            }
            broadcasted = true;
        }
    }
    CLOG_TRACE(Overlay, "broadcast {} told {}", hexAbbrev(index),
               peersTold.size());
    return broadcasted;
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
            CLOG_TRACE(Overlay,
                       "{} marking message {} advertized by {} known (but "
                       "don't have it)",
                       mId, hexAbbrev(h),
                       KeyUtils::toShortString(fromPeer->getPeerID()));
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
                CLOG_TRACE(Overlay,
                           "{} know of message {} advertized by {} and already "
                           "have it",
                           mId, hexAbbrev(h),
                           KeyUtils::toShortString(fromPeer->getPeerID()));
            }
            else
            {
                CLOG_TRACE(
                    Overlay,
                    "{} know of message {} advertized by {} and don't have it",
                    mId, hexAbbrev(h),
                    KeyUtils::toShortString(fromPeer->getPeerID()));
            }
        }
        if (mPendingDemanded.find(h) != mPendingDemanded.end())
        {
            CLOG_TRACE(Overlay, "{} already demanded {} advertized by {}", mId,
                       hexAbbrev(h),
                       KeyUtils::toShortString(fromPeer->getPeerID()));
        }
        if (!haveMessage && mPendingDemanded.find(h) == mPendingDemanded.end())
        {
            CLOG_TRACE(Overlay, "{} demanding {} from {}", mId, hexAbbrev(h),
                       KeyUtils::toShortString(fromPeer->getPeerID()));
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
                CLOG_TRACE(Overlay,
                           "{} fulfilling demand for {} demanded by {}", mId,
                           hexAbbrev(h),
                           KeyUtils::toShortString(fromPeer->getPeerID()));
                mMessagesFulfilled.Mark();
                fromPeer->sendMessage(*(i->second->mMessage));
            }
            else
            {
                CLOG_TRACE(Overlay,
                           "{} can't fulfill demand for {} demanded by {} -- "
                           "know of message but don't have it",
                           mId, hexAbbrev(h),
                           KeyUtils::toShortString(fromPeer->getPeerID()));
            }
        }
        else
        {
            CLOG_TRACE(Overlay,
                       "can't fulfill demand for {} demanded by {} -- don't "
                       "know of message",
                       mId, hexAbbrev(h),
                       KeyUtils::toShortString(fromPeer->getPeerID()));
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
    CLOG_TRACE(Overlay, "{} forgetting {}", mId, hexAbbrev(h));
    mFloodMap.erase(h);
    mPendingDemanded.erase(h);
}

void
Floodgate::updateRecord(StellarMessage const& oldMsg,
                        StellarMessage const& newMsg)
{
    ZoneScoped;
    Hash oldHash = xdrBlake2(oldMsg);
    Hash newHash = xdrBlake2(newMsg);

    auto oldIter = mFloodMap.find(oldHash);
    if (oldIter != mFloodMap.end())
    {
        auto record = oldIter->second;
        *record->mMessage = newMsg;

        mFloodMap.erase(oldIter);
        mFloodMap.emplace(newHash, record);
    }
}
}
