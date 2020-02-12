// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "overlay/Floodgate.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "herder/Herder.h"
#include "ledger/LedgerManager.h"
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
                                    uint64_t keyedShortHash,
                                    uint64_t unkeyedShortHash)
    : mLedgerSeq(ledger)
    , mMessage(msg)
    , mKeyedShortHash(keyedShortHash)
    , mUnkeyedShortHash(unkeyedShortHash)
{
}

Floodgate::Floodgate(Application& app)
    : mApp(app)
    , mFloodMapSize(
          app.getMetrics().NewCounter({"overlay", "memory", "flood-known"}))
    , mPendingDemandsSize(
          app.getMetrics().NewCounter({"overlay", "memory", "pending-demands"}))
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
    size_t FLOOD_MEMORY_LEDGERS = 10;
    for (auto it = mFloodMap.cbegin(); it != mFloodMap.cend();)
    {
        auto record = it->second;
        // give ten ledgers of leeway
        if (record->mLedgerSeq + FLOOD_MEMORY_LEDGERS < currentLedger)
        {
            mPendingDemands.erase(record->mKeyedShortHash);
            mPendingDemands.erase(record->mUnkeyedShortHash);
            mShortHashFloodMap.erase(record->mKeyedShortHash);
            mShortHashFloodMap.erase(record->mUnkeyedShortHash);
            it = mFloodMap.erase(it);
        }
        else
        {
            ++it;
        }
    }

    for (auto it = mPendingDemands.cbegin(); it != mPendingDemands.cend();)
    {
        // We clear a _pending_ demand entry after only _one_ ledger of leeway:
        // any demand should be almost-immediately fulfilled and if it's not
        // we're probably dealing with a flaky (or misbehaving) peer and we
        // want to re-open ourselves after a ledger to getting the same message
        // from someone else.
        if (it->second + 1 < currentLedger)
        {
            it = mPendingDemands.erase(it);
        }
        else
        {
            ++it;
        }
    }
    assert(mShortHashFloodMap.size() <=
           (mFloodMap.size() * FLOOD_MEMORY_LEDGERS * 2));
    mFloodMapSize.set_count(mFloodMap.size());
    mPendingDemandsSize.set_count(mPendingDemands.size());
}

std::pair<std::map<Hash, Floodgate::FloodRecord::pointer>::iterator, bool>
Floodgate::insert(StellarMessage const& msg, bool force)
{
    Hash index = xdrSha256(msg);
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

    Hash LCLHash = mApp.getLedgerManager().getLastClosedLedgerHeader().hash;
    Hash zeroHash;
    uint64_t keyedShortHash =
        shortHash::xdrComputeKeyedHash(msg, ByteSlice(LCLHash.data(), 16));
    uint64_t unkeyedShortHash =
        shortHash::xdrComputeKeyedHash(msg, ByteSlice(zeroHash.data(), 16));

    mPendingDemands.erase(keyedShortHash);
    mPendingDemands.erase(unkeyedShortHash);
    mPendingDemandsSize.set_count(mPendingDemands.size());

    FloodRecord::pointer rec = std::make_shared<FloodRecord>(
        msg, seq, keyedShortHash, unkeyedShortHash);
    mShortHashFloodMap.emplace(keyedShortHash, rec);
    mShortHashFloodMap.emplace(unkeyedShortHash, rec);
    auto ret = mFloodMap.emplace(index, rec);
    assert(ret.second);
    mFloodMapSize.set_count(mFloodMap.size());
    return ret;
}

bool
Floodgate::addRecord(StellarMessage const& msg, Peer::pointer peer, Hash& index)
{
    if (mShuttingDown)
    {
        index = xdrSha256(msg);
        return false;
    }
    auto pair = insert(msg);
    index = pair.first->first;
    FloodRecord::pointer record = pair.first->second;
    if (peer)
    {
        record->mPeersTold.insert(peer->toString());
    }
    return pair.second;
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
    auto pair = insert(msg, force);
    Hash const& index = pair.first->first;
    FloodRecord::pointer record = pair.first->second;

    CLOG(TRACE, "Overlay") << "broadcast " << hexAbbrev(index);

    // Send (or at least advertize) it to people that haven't sent it to us
    // and/or we haven't sent it to in full. We _might_ advertize the same
    // message to the same peer twice if we somehow receive it twice and decide
    // to call broadcast() twice before sending it to them; but we should only
    // really be broadcast()'ing new messages anyway in our caller.
    auto& peersTold = record->mPeersTold;

    // make a copy, in case peers gets modified
    auto peers = mApp.getOverlayManager().getAuthenticatedPeers();

    for (auto& peer : peers)
    {
        assert(peer.second->isAuthenticated());
        if (peersTold.find(peer.second->toString()) == peersTold.end() &&
            peer.second->getRemoteOverlayVersion() >= minOverlayVersion)
        {
            if (peer.second->supportsAdverts())
            {
                uint64_t shortHash =
                    (mApp.getState() == Application::State::APP_SYNCED_STATE
                         ? record->mKeyedShortHash
                         : record->mUnkeyedShortHash);
                CLOG(TRACE, "Overlay")
                    << mId << " advertizing " << shortHash << " to "
                    << KeyUtils::toShortString(peer.second->getPeerID());
                mMessagesAdvertized.Mark();
                peer.second->advertizeMessage(shortHash);
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
    for (uint64_t h : adv.hashes)
    {
        auto i = mShortHashFloodMap.find(h);
        if (i != mShortHashFloodMap.end())
        {
            // We already got a full message for h; record that fromPeer also
            // has the message, to inhibit advertizing or sending to fromPeer.
            i->second->mPeersTold.insert(fromPeer->toString());
            CLOG(TRACE, "Overlay")
                << mId << " already have full message for " << h
                << " advertized by "
                << KeyUtils::toShortString(fromPeer->getPeerID());
        }
        else if (mPendingDemands.find(h) != mPendingDemands.end())
        {
            // We don't have this message but we did already ask for it from
            // someone else, so we'll avoid asking for it here.
            //
            // TODO: for security / poison-avoidance here, we might want to
            // ask more than once or keep track of how long it's been since we
            // asked.
            CLOG(TRACE, "Overlay")
                << mId << " already demanded " << h << " advertized by "
                << KeyUtils::toShortString(fromPeer->getPeerID());
        }
        else
        {
            CLOG(TRACE, "Overlay")
                << mId << " demanding " << h << " from "
                << KeyUtils::toShortString(fromPeer->getPeerID());
            // We don't have this message in full and haven't demanded it yet
            // from anyone who advertized it; ask now and leave a record that
            // we've done so to avoid demanding it from others.
            mMessagesDemanded.Mark();
            mPendingDemands.emplace(h, mApp.getHerder().getCurrentLedgerSeq());
            mPendingDemandsSize.set_count(mPendingDemands.size());
            demand.hashes.emplace_back(h);
        }
    }
    fromPeer->sendMessage(msg);
}

void
Floodgate::fulfillDemand(FloodDemand const& dmd, Peer::pointer fromPeer)
{
    for (uint64_t h : dmd.hashes)
    {
        auto i = mShortHashFloodMap.find(h);
        if (i == mShortHashFloodMap.end())
        {
            CLOG(TRACE, "Overlay")
                << mId << " can't fulfill demand for " << h << " demanded by "
                << KeyUtils::toShortString(fromPeer->getPeerID())
                << " -- don't know of message";
        }
        else
        {
            CLOG(TRACE, "Overlay")
                << mId << " fulfilling demand for " << h << " demanded by "
                << KeyUtils::toShortString(fromPeer->getPeerID());
            mMessagesFulfilled.Mark();
            i->second->mPeersTold.insert(fromPeer->toString());
            fromPeer->sendMessage(i->second->mMessage);
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
    mShortHashFloodMap.clear();
    mPendingDemands.clear();
}

void
Floodgate::forgetRecord(Hash const& h)
{
    CLOG(TRACE, "Overlay") << mId << " forgetting " << hexAbbrev(h);
    auto i = mFloodMap.find(h);
    if (i != mFloodMap.end())
    {
        auto record = i->second;
        mShortHashFloodMap.erase(record->mKeyedShortHash);
        mShortHashFloodMap.erase(record->mUnkeyedShortHash);
        mPendingDemands.erase(record->mKeyedShortHash);
        mPendingDemands.erase(record->mUnkeyedShortHash);
        mPendingDemandsSize.set_count(mPendingDemands.size());
        mFloodMap.erase(i);
        mFloodMapSize.set_count(mFloodMap.size());
    }
}
}
