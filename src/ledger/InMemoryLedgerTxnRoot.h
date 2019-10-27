#include "ledger/LedgerTxn.h"
#include "xdr/Stellar-ledger-entries.h"
#include <unordered_map>
#include <vector>
#include <set>
#include <map>

// This is a helper class that implements a "root" LedgerTxnParent like
// LedgerTxnRoot but only storing its entries directly in memory. Nothing
// durable. It's useful for replay but should never be used if you need to
// _store_ the ledger being transacted-upon.

namespace stellar
{

class InMemoryLedgerTxnRoot : public AbstractLedgerTxnParent
{
    using EntryMap = std::unordered_map<LedgerKey, std::shared_ptr<LedgerEntry const>>;
    using MapValueType = typename EntryMap::value_type;

    struct BestOfferComparator
    {
        bool operator()(MapValueType* const& lhs,
                        MapValueType* const& rhs) const
        {
            return isBetterOffer(*lhs->second, *rhs->second);
        }
    };

    mutable EntryMap mNonOffers;
    mutable EntryMap mOffers;
    mutable std::map<std::pair<Asset,Asset>, std::set<MapValueType*, BestOfferComparator>> mBestOffers;
    mutable std::unique_ptr<LedgerHeader> mHeader;
    mutable AbstractLedgerTxn *mChild{nullptr};

    void addToBestOffers(MapValueType* p) const;
    void removeFromBestOffers(MapValueType* p) const;

public:
    InMemoryLedgerTxnRoot();
    void addChild(AbstractLedgerTxn& child) override;
    void commitChild(EntryIterator iter, LedgerTxnConsistency cons) override;
    void rollbackChild() override;

    std::unordered_map<LedgerKey, LedgerEntry> getAllOffers() override;
    std::shared_ptr<LedgerEntry const>
    getBestOffer(Asset const& buying, Asset const& selling,
                 std::unordered_set<LedgerKey>& exclude) override;
    std::unordered_map<LedgerKey, LedgerEntry>
    getOffersByAccountAndAsset(AccountID const& account,
                               Asset const& asset) override;

    LedgerHeader const& getHeader() const override;

    std::vector<InflationWinner>
    getInflationWinners(size_t maxWinners, int64_t minBalance) override;

    std::shared_ptr<LedgerEntry const>
    getNewestVersion(LedgerKey const& key) const override;

    uint64_t countObjects(LedgerEntryType let) const override;
    uint64_t countObjects(LedgerEntryType let,
                                  LedgerRange const& ledgers) const override;

    void deleteObjectsModifiedOnOrAfterLedger(uint32_t ledger) const override;

    void dropAccounts() override;
    void dropData() override;
    void dropOffers() override;
    void dropTrustLines() override;

};

}
