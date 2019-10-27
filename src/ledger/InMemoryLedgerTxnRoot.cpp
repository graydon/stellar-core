#include "ledger/LedgerTxn.h"
#include "ledger/LedgerRange.h"
#include "ledger/InMemoryLedgerTxnRoot.h"
#include "xdr/Stellar-ledger-entries.h"
#include "util/XDROperators.h"
#include "util/types.h"
#include "xdrpp/marshal.h"
#include <algorithm>

namespace stellar
{

InMemoryLedgerTxnRoot::InMemoryLedgerTxnRoot()
    : mHeader(std::make_unique<LedgerHeader>()),
      mChild(nullptr)
{
}

void
InMemoryLedgerTxnRoot::addChild(AbstractLedgerTxn& child)
{
    assert(!mChild);
    mChild = &child;
}

void
InMemoryLedgerTxnRoot::addToBestOffers(MapValueType* p) const
{
    auto const& offerVal = p->second->data.offer();
    auto key = std::make_pair(offerVal.buying, offerVal.selling);
    mBestOffers[key].insert(p);
}

void
InMemoryLedgerTxnRoot::removeFromBestOffers(MapValueType* p) const
{
    auto const& offerVal = p->second->data.offer();
    auto key = std::make_pair(offerVal.buying, offerVal.selling);
    mBestOffers[key].erase(p);
}

void
InMemoryLedgerTxnRoot::commitChild(EntryIterator iter, LedgerTxnConsistency cons)
{
    while (iter)
    {
        if (iter.entryExists())
        {
            if (iter.key().type() == OFFER)
            {
                auto i = mOffers.find(iter.key());
                if (i != mOffers.end())
                {
                    removeFromBestOffers(&(*i));
                }
                mOffers[iter.key()] = std::make_shared<LedgerEntry>(iter.entry());
                addToBestOffers(&(*mOffers.find(iter.key())));
            }
            else
            {
                mNonOffers[iter.key()] = std::make_shared<LedgerEntry>(iter.entry());
            }
        }
        else
        {
            if (iter.key().type() == OFFER)
            {
                auto i = mOffers.find(iter.key());
                if (i != mOffers.end())
                {
                    removeFromBestOffers(&(*i));
                }
                mOffers.erase(iter.key());
            }
            else
            {
                mNonOffers.erase(iter.key());
            }
        }
        ++iter;
    }
    assert(mChild);
    mHeader = std::make_unique<LedgerHeader>(mChild->getHeader());
    mChild = nullptr;
}

void
InMemoryLedgerTxnRoot::rollbackChild()
{
    mHeader = std::make_unique<LedgerHeader>();
    mChild = nullptr;
}


std::unordered_map<LedgerKey, LedgerEntry>
InMemoryLedgerTxnRoot::getAllOffers()
{
    std::unordered_map<LedgerKey, LedgerEntry> ret;
    for (auto const& kv : mOffers)
    {
        ret.emplace(kv.first, *kv.second);
    }
    return ret;
}

std::shared_ptr<LedgerEntry const>
InMemoryLedgerTxnRoot::getBestOffer(Asset const& buying, Asset const& selling,
                                    std::unordered_set<LedgerKey>& exclude)
{
    auto key = std::make_pair(buying, selling);
    auto const& s = mBestOffers[key];
    for (auto i = s.begin(); i != s.end(); ++i)
    {
        if (exclude.find((*i)->first) == exclude.end())
        {
            return (*i)->second;
        }
    }
    return nullptr;
}

std::unordered_map<LedgerKey, LedgerEntry>
InMemoryLedgerTxnRoot::getOffersByAccountAndAsset(AccountID const& account,
                                                  Asset const& asset)
{
    std::unordered_map<LedgerKey, LedgerEntry> ret;
    for (auto const& kv : mOffers)
    {
        auto const &offerKey = kv.first.offer();
        auto const &offerVal = kv.second->data.offer();
        if (offerVal.selling == asset &&
            offerKey.sellerID == account)
        {
            ret.emplace(kv.first, *kv.second);
        }
    }
    return ret;
}

LedgerHeader const&
InMemoryLedgerTxnRoot::getHeader() const
{
    return *mHeader;
}


std::vector<InflationWinner>
InMemoryLedgerTxnRoot::getInflationWinners(size_t maxWinners, int64_t minBalance)
{
    std::vector<InflationWinner> ret;
    std::map<AccountID, int64_t> votes;
    for (auto const& kv : mNonOffers)
    {
        if (kv.second->data.type() != ACCOUNT)
        {
            continue;
        }
        auto const& account = kv.second->data.account();
        if (account.balance < 1000000000 ||
            !account.inflationDest)
        {
            continue;
        }
        votes[*account.inflationDest] += account.balance;
    }
    for (auto const& kv : votes)
    {
        if (kv.second >= minBalance)
        {
            ret.emplace_back(InflationWinner{kv.first, kv.second});
        }
    }
    std::sort(ret.begin(), ret.end(),
              [](InflationWinner const& a,
                 InflationWinner const& b)
                  {
                      return (b.votes < a.votes) ||
                          ((b.votes == a.votes) &&
                           (b.accountID < a.accountID));
                  });
    return ret;
}

std::shared_ptr<LedgerEntry const>
InMemoryLedgerTxnRoot::getNewestVersion(LedgerKey const& key) const
{
    if (key.type() == OFFER)
    {
        auto i = mOffers.find(key);
        return (i == mOffers.end()) ? nullptr : i->second;
    }
    else
    {
        auto i = mNonOffers.find(key);
        return (i == mNonOffers.end()) ? nullptr : i->second;
    }
}

uint64_t
InMemoryLedgerTxnRoot::countObjects(LedgerEntryType let) const
{
    if (let == OFFER)
    {
        return mOffers.size();
    }
    else
    {
        uint64_t i = 0;
        for (auto const& kv : mNonOffers)
        {
            if (kv.first.type() == let)
            {
                ++i;
            }
        }
        return i;
    }
}

uint64_t
InMemoryLedgerTxnRoot::countObjects(LedgerEntryType let,
                                    LedgerRange const& ledgers) const
{
    auto const& tab = ((let == OFFER) ? mOffers : mNonOffers);
    uint64_t i = 0;
    for (auto const& kv : tab)
    {
        if (kv.first.type() == let &&
            kv.second->lastModifiedLedgerSeq >= ledgers.mFirst &&
            kv.second->lastModifiedLedgerSeq <= ledgers.mLast)
        {
            ++i;
        }
    }
    return i;
}

void
InMemoryLedgerTxnRoot::deleteObjectsModifiedOnOrAfterLedger(uint32_t ledger) const
{
    for (auto i = mOffers.begin(); i != mOffers.end();)
    {
        auto curr = i;
        ++i;
        assert(curr->second);
        if (curr->second->lastModifiedLedgerSeq >= ledger)
        {
            removeFromBestOffers(&(*curr));
            mOffers.erase(curr);
        }
    }
    for (auto i = mNonOffers.begin(); i != mNonOffers.end();)
    {
        auto curr = i;
        ++i;
        assert(curr->second);
        if (curr->second->lastModifiedLedgerSeq >= ledger)
        {
            mNonOffers.erase(curr);
        }
    }
}

void
InMemoryLedgerTxnRoot::dropAccounts()
{
    for (auto i = mNonOffers.begin(); i != mNonOffers.end();)
    {
        auto curr = i;
        ++i;
        assert(curr->second);
        if (curr->second->data.type() == ACCOUNT)
        {
            mNonOffers.erase(curr);
        }
    }
}

void
InMemoryLedgerTxnRoot::dropData()
{
    for (auto i = mNonOffers.begin(); i != mNonOffers.end();)
    {
        auto curr = i;
        ++i;
        assert(curr->second);
        if (curr->second->data.type() == DATA)
        {
            mNonOffers.erase(curr);
        }
    }
}

void
InMemoryLedgerTxnRoot::dropOffers()
{
    mOffers.clear();
    mBestOffers.clear();
}

void
InMemoryLedgerTxnRoot::dropTrustLines()
{
    for (auto i = mNonOffers.begin(); i != mNonOffers.end();)
    {
        auto curr = i;
        ++i;
        assert(curr->second);
        if (curr->second->data.type() == TRUSTLINE)
        {
            mNonOffers.erase(curr);
        }
    }
}

}
