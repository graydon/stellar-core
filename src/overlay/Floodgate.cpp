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
Floodgate::FloodRecord::FloodRecord(std::optional<StellarMessage> const& msg, uint32_t ledger,
                                    Peer::pointer peer)
    : mLedgerSeq(ledger), mMessage(msg)
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
    , mShuttingDown(false)
{
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
            it = mFloodMap.erase(it);
        }
        else
        {
            ++it;
        }
    }
    mFloodMapSize.set_count(mFloodMap.size());
}

std::pair<std::map<Hash, Floodgate::FloodRecord::pointer>::iterator, bool>
Floodgate::insert(Hash const& index, std::optional<StellarMessage> const& msg, bool force)
{
    auto seq = mApp.getHerder().getCurrentLedgerSeq();
    auto iter = mFloodMap.find(index);
    if (iter != mFloodMap.end())
    {
        if (force)
        {
            // "Force" means "clear the mPeersTold and reset seq" when there's
            // an existing entry.
            iter->second->mPeersTold.clear();
            iter->second->mLedgerSeq = seq;
        }
        return std::make_pair(iter, false);
    }

    FloodRecord::pointer rec = std::make_shared<FloodRecord>(
        msg, seq);
    auto ret = mFloodMap.emplace(index, rec);
    assert(ret.second);
    mFloodMapSize.set_count(mFloodMap.size());
    TracyPlot("overlay.memory.flood-known",
                static_cast<int64_t>(mFloodMap.size()));
    return ret;
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
    auto pair = insert(index, msg);
    FloodRecord::pointer record = pair.first->second;
    if (peer)
    {
        record->mPeersTold.insert(peer->toString());
    }
    return pair.second;
}

void
Floodgate::alreadyHave(Peer::pointer fromPeer, AlreadyHaveMessage const& have)
{
    ZoneScoped;
    if (mShuttingDown)
    {
        return;
    }
    std::string peerId = fromPeer->toString();
    for (auto const& index : have.hashes)
    {
        auto pair = insert(index, std::nullopt);
        FloodRecord::pointer record = pair.first->second;
        record->mPeersTold.insert(peerId);
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
    FloodRecord::pointer fr = insert(index, msg, force).first->second;
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
            mSendFromBroadcast.Mark();
            std::weak_ptr<Peer> weak(
                std::static_pointer_cast<Peer>(peer.second));
            mApp.postOnMainThread(
                [smsg, weak, log = !broadcasted]() {
                    auto strong = weak.lock();
                    if (strong)
                    {
                        strong->sendMessage(*smsg, log);
                    }
                },
                fmt::format("broadcast to {}", peer.second->toString()));
            broadcasted = true;
        }
    }
    CLOG_TRACE(Overlay, "broadcast {} told {}", hexAbbrev(index),
               peersTold.size());
    return broadcasted;
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
    mFloodMap.erase(h);
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
        record->mMessage = newMsg;

        mFloodMap.erase(oldIter);
        mFloodMap.emplace(newHash, record);
    }
}
}
