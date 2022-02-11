#include "ledger/ConcurrentTxPartition.h"
#include "ledger/LedgerTxn.h"
#include "transactions/TransactionUtils.h"
#include "util/BitSet.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "xdr/Stellar-ledger-entries.h"
#include "xdr/Stellar-transaction.h"
#include "xdr/Stellar-types.h"
#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <variant>

// First, a textbook disjoint-sets / union-find implementation.
// https://en.wikipedia.org/wiki/Disjoint-set_data_structure
//
// Augmented with an optional RootData type that we merge upwards,
// carrying some user data.
using SetID = size_t;

template <typename RootData> struct Set
{
    SetID mParent;
    size_t mSize;
    std::optional<RootData> mRootData{std::nullopt};
    Set(SetID self) : mParent(self), mSize(1)
    {
    }
};

template <typename RootData> struct SetPartition
{
    std::vector<Set<RootData>> mSets;

    SetID
    add()
    {
        SetID n = mSets.size();
        mSets.emplace_back(Set<RootData>(n));
        return n;
    }

    SetID
    find(SetID x)
    {
        SetID root = x;
        while (mSets.at(root).mParent != root)
        {
            using namespace stellar;
            releaseAssert(!mSets.at(root).mRootData);
            root = mSets.at(root).mParent;
        }
        while (mSets.at(x).mParent != root)
        {
            auto parent = mSets.at(x).mParent;
            mSets.at(x).mParent = root;
            x = parent;
        }
        return root;
    }

    RootData&
    getRootData(SetID x)
    {
        x = find(x);
        auto& s = mSets.at(x);
        if (!s.mRootData)
        {
            s.mRootData.emplace();
        }
        return *s.mRootData;
    }

    void
    join(SetID x, SetID y)
    {

        x = find(x);
        y = find(y);

        if (x == y)
        {
            return;
        }

        if (mSets.at(x).mSize < mSets.at(y).mSize)
        {
            std::swap(x, y);
        }
        auto& setX = mSets.at(x);
        auto& setY = mSets.at(y);
        setY.mParent = x;
        setX.mSize += setY.mSize;
        if (setY.mRootData)
        {
            if (setX.mRootData)
            {
                (*setX.mRootData).merge(*setY.mRootData);
                setY.mRootData.reset();
            }
            else
            {
                setX.mRootData.swap(setY.mRootData);
            }
        }
    }

    // For diagnostic logging: enumerate the roots.
    BitSet
    getRoots()
    {
        BitSet res;
        for (size_t i = 0; i < mSets.size(); ++i)
        {
            res.set(find(i));
        }
        return res;
    }
};

// Next, a set of helpers to perform data-dependency
// analysis of a set of txs, so that we know what they
// are going to read and write.

namespace std
{
template <> class hash<stellar::AssetPair>
{
  public:
    size_t
    operator()(stellar::AssetPair const& pair) const
    {
        stellar::AssetPairHash h;
        return h(pair);
    }
};
}
namespace stellar
{

using DataID = size_t;
using TxID = size_t;

enum class AccessMode
{
    READ,
    WRITE
};

using DataKey = std::variant<LedgerKey, AssetPair>;

struct DataDependencyAnalyzer
{
    DataDependencyAnalyzer(size_t nTxs) : mReadSets(nTxs), mWriteSets(nTxs)
    {
    }
    std::unordered_map<DataKey, DataID> keyToDataId;
    DataID
    getID(DataKey const& k)
    {
        DataID next = keyToDataId.size();
        auto pair = keyToDataId.emplace(k, next);
        return pair.first->second;
    }
    std::vector<BitSet> mReadSets;
    std::vector<BitSet> mWriteSets;
    BitSet
    getAccessedData(TxID tx) const
    {
        return mReadSets.at(tx) | mWriteSets.at(tx);
    }
    void
    recordDependency(TxID txID, DataKey const& dep, AccessMode mode)
    {
        std::vector<BitSet>& sets =
            (mode == AccessMode::READ) ? mReadSets : mWriteSets;
        DataID data = getID(dep);
        CLOG_DEBUG(Ledger, "Tx {} {}-depends on data {}", txID,
                   (mode == AccessMode::READ) ? "read" : "write", data);
        sets.at(txID).set(data);
    }
};

struct SingleTxAnalyzer
{
    DataDependencyAnalyzer& mDDA;
    TxID mTxID;

    // FIXME: for this generation we're just experimenting so we can skip cases
    // we don't want to analyze and we'll just filter them out of the analysis.
    bool mSkip{false};

    SingleTxAnalyzer(DataDependencyAnalyzer& dda, TxID txID)
        : mDDA(dda), mTxID(txID)
    {
    }

    void
    recordDependency(DataKey const& key, AccessMode mode)
    {
        DataKey k(key);
        if (std::holds_alternative<AssetPair>(k))
        {
            using namespace xdr;
            // each asset-pair is normalized to a single direction
            // with buying < selling.
            AssetPair& ap = std::get<AssetPair>(k);
            if (!(ap.buying < ap.selling))
            {
                std::swap(ap.buying, ap.selling);
            }
        }
        mDDA.recordDependency(mTxID, k, mode);
    }

    void
    analyzeEd25519Account(uint256 const& ed25519Key, AccessMode mode)
    {
        LedgerKey k;
        k.type(ACCOUNT);
        k.account().accountID.type(PUBLIC_KEY_TYPE_ED25519);
        k.account().accountID.ed25519() = ed25519Key;
        recordDependency(k, mode);
    }

    void
    analyzePublicKey(PublicKey const& pk, AccessMode mode)
    {
        switch (pk.type())
        {
        case PUBLIC_KEY_TYPE_ED25519:
            analyzeEd25519Account(pk.ed25519(), mode);
            break;
        default:
            mSkip = true;
        }
    }
    void
    analyzeAccountID(AccountID const& acct, AccessMode mode)
    {
        analyzePublicKey(acct, mode);
    }

    void
    analyzeMuxedAccount(MuxedAccount const& ma, AccessMode mode)
    {
        switch (ma.type())
        {
        case KEY_TYPE_ED25519:
            analyzeEd25519Account(ma.ed25519(), mode);
            break;
        case KEY_TYPE_MUXED_ED25519:
            analyzeEd25519Account(ma.med25519().ed25519, mode);
        default:
            mSkip = true;
        }
    }

    TrustLineAsset
    assetToTrustLineAsset(Asset const& a)
    {
        TrustLineAsset tla;
        tla.type(a.type());
        switch (a.type())
        {
        case ASSET_TYPE_CREDIT_ALPHANUM4:
            tla.alphaNum4() = a.alphaNum4();
            break;
        case ASSET_TYPE_CREDIT_ALPHANUM12:
            tla.alphaNum12() = a.alphaNum12();
            break;
        default:
            break;
        }
        return tla;
    }

    void
    analyzeTrustLineAsset(TrustLineAsset const& tla, AccessMode mode)
    {
        LedgerKey k;
        switch (tla.type())
        {
        case ASSET_TYPE_NATIVE:
            break;
        case ASSET_TYPE_CREDIT_ALPHANUM4:
            k.type(ACCOUNT);
            k.account().accountID = tla.alphaNum4().issuer;
            recordDependency(k, mode);
            break;
        case ASSET_TYPE_CREDIT_ALPHANUM12:
            k.type(ACCOUNT);
            k.account().accountID = tla.alphaNum12().issuer;
            recordDependency(k, mode);
            break;
        case ASSET_TYPE_POOL_SHARE:
            k.type(LIQUIDITY_POOL);
            k.liquidityPool().liquidityPoolID = tla.liquidityPoolID();
            recordDependency(k, mode);
            break;
        }
    }

    void
    analyzeAsset(Asset const& asset, AccessMode mode)
    {
        analyzeTrustLineAsset(assetToTrustLineAsset(asset), mode);
    }

    void
    analyzeNativeBalanceOrTrustline(AccountID const& account,
                                    TrustLineAsset const& tla, AccessMode mode)
    {
        if (tla.type() == ASSET_TYPE_NATIVE)
        {
            analyzeAccountID(account, mode);
        }
        else
        {
            // read the asset-issuer itself
            analyzeTrustLineAsset(tla, AccessMode::READ);

            // read or write a balance-of-this-asset
            LedgerKey k;
            k.type(TRUSTLINE);
            k.trustLine().accountID = account;
            k.trustLine().asset = tla;
            recordDependency(k, mode);
        }
    }

    std::optional<AccountID>
    getAccountInMuxedAccount(MuxedAccount const& ma)
    {
        AccountID acct;
        switch (ma.type())
        {
        case KEY_TYPE_ED25519:
            acct.type(PUBLIC_KEY_TYPE_ED25519);
            acct.ed25519() = ma.ed25519();
            return std::make_optional(acct);
        case KEY_TYPE_MUXED_ED25519:
            acct.type(PUBLIC_KEY_TYPE_ED25519);
            acct.ed25519() = ma.med25519().ed25519;
            return std::make_optional(acct);
        default:
            break;
        }
        return std::nullopt;
    }

    void
    analyzeOperation(MuxedAccount const& sender, Operation const& op)
    {
        if (op.sourceAccount)
        {
            analyzeMuxedAccount(*op.sourceAccount, AccessMode::WRITE);
        }
        switch (op.body.type())
        {

        case CREATE_ACCOUNT:
            analyzeAccountID(op.body.createAccountOp().destination,
                             AccessMode::WRITE);
            break;

        case PAYMENT:
        {
            auto const& payop = op.body.paymentOp();
            auto srcAcct = getAccountInMuxedAccount(
                op.sourceAccount ? *op.sourceAccount : sender);
            auto dstAcct = getAccountInMuxedAccount(payop.destination);
            auto tla = assetToTrustLineAsset(payop.asset);
            if (srcAcct)
            {
                analyzeNativeBalanceOrTrustline(*srcAcct, tla,
                                                AccessMode::WRITE);
            }
            if (dstAcct)
            {
                analyzeNativeBalanceOrTrustline(*dstAcct, tla,
                                                AccessMode::WRITE);
            }
        }
        break;

        case PATH_PAYMENT_STRICT_RECEIVE:
        {
            auto const& pathop = op.body.pathPaymentStrictReceiveOp();
            analyzeAsset(pathop.sendAsset, AccessMode::READ);
            analyzeAsset(pathop.destAsset, AccessMode::READ);
            auto srcAcct = getAccountInMuxedAccount(
                op.sourceAccount ? *op.sourceAccount : sender);
            auto dstAcct = getAccountInMuxedAccount(pathop.destination);
            Asset srcAsset = pathop.sendAsset;
            Asset dstAsset = pathop.destAsset;
            TrustLineAsset srcTla = assetToTrustLineAsset(srcAsset);
            TrustLineAsset dstTla = assetToTrustLineAsset(dstAsset);
            if (srcAcct)
            {
                analyzeNativeBalanceOrTrustline(*srcAcct, srcTla,
                                                AccessMode::WRITE);
            }
            if (dstAcct)
            {
                analyzeNativeBalanceOrTrustline(*dstAcct, dstTla,
                                                AccessMode::WRITE);
            }
            Asset prev = srcAsset;
            for (Asset a : pathop.path)
            {
                recordDependency(AssetPair{prev, a}, AccessMode::WRITE);
                prev = a;
            }
            recordDependency(AssetPair{prev, dstAsset}, AccessMode::WRITE);
        }
        break;

        case PATH_PAYMENT_STRICT_SEND:
        {
            auto const& pathop = op.body.pathPaymentStrictSendOp();
            analyzeAsset(pathop.sendAsset, AccessMode::READ);
            analyzeAsset(pathop.destAsset, AccessMode::READ);
            auto srcAcct = getAccountInMuxedAccount(
                op.sourceAccount ? *op.sourceAccount : sender);
            auto dstAcct = getAccountInMuxedAccount(pathop.destination);
            Asset srcAsset = pathop.sendAsset;
            Asset dstAsset = pathop.destAsset;
            TrustLineAsset srcTla = assetToTrustLineAsset(srcAsset);
            TrustLineAsset dstTla = assetToTrustLineAsset(dstAsset);
            if (srcAcct)
            {
                analyzeNativeBalanceOrTrustline(*srcAcct, srcTla,
                                                AccessMode::WRITE);
            }
            if (dstAcct)
            {
                analyzeNativeBalanceOrTrustline(*dstAcct, dstTla,
                                                AccessMode::WRITE);
            }
            Asset prev = srcAsset;
            for (Asset a : pathop.path)
            {
                recordDependency(AssetPair{prev, a}, AccessMode::WRITE);
                prev = a;
            }
            recordDependency(AssetPair{prev, dstAsset}, AccessMode::WRITE);
        }
        break;

        case MANAGE_SELL_OFFER:
        {
            Asset buying = op.body.manageSellOfferOp().buying;
            Asset selling = op.body.manageSellOfferOp().selling;
            analyzeAsset(buying, AccessMode::READ);
            analyzeAsset(selling, AccessMode::READ);
            recordDependency(AssetPair{buying, selling}, AccessMode::WRITE);
        }
        break;

        case MANAGE_BUY_OFFER:
        {
            Asset buying = op.body.manageBuyOfferOp().buying;
            Asset selling = op.body.manageBuyOfferOp().selling;
            analyzeAsset(buying, AccessMode::READ);
            analyzeAsset(selling, AccessMode::READ);
            recordDependency(AssetPair{buying, selling}, AccessMode::WRITE);
        }
        break;

        case CREATE_PASSIVE_SELL_OFFER:
        {
            Asset buying = op.body.createPassiveSellOfferOp().buying;
            Asset selling = op.body.createPassiveSellOfferOp().selling;
            analyzeAsset(buying, AccessMode::READ);
            analyzeAsset(selling, AccessMode::READ);
            recordDependency(AssetPair{buying, selling}, AccessMode::WRITE);
        }
        break;

        default:
            mSkip = true;
            break;

            /*
                // TODO: finish other op types

                SET_OPTIONS = 5,
                CHANGE_TRUST = 6,
                ALLOW_TRUST = 7,
                ACCOUNT_MERGE = 8,
                INFLATION = 9,
                MANAGE_DATA = 10,
                BUMP_SEQUENCE = 11,
                CREATE_CLAIMABLE_BALANCE = 14,
                CLAIM_CLAIMABLE_BALANCE = 15,
                BEGIN_SPONSORING_FUTURE_RESERVES = 16,
                END_SPONSORING_FUTURE_RESERVES = 17,
                REVOKE_SPONSORSHIP = 18,
                CLAWBACK = 19,
                CLAWBACK_CLAIMABLE_BALANCE = 20,
                SET_TRUST_LINE_FLAGS = 21,
                LIQUIDITY_POOL_DEPOSIT = 22,
                LIQUIDITY_POOL_WITHDRAW = 23
            */
        }
    }

    void
    analyzeTx(TransactionEnvelope const& tx)
    {
        switch (tx.type())
        {
        case ENVELOPE_TYPE_TX:
            // WRITE-mode because we charge a fee.
            analyzeMuxedAccount(tx.v1().tx.sourceAccount, AccessMode::WRITE);
            for (auto const& op : tx.v1().tx.operations)
            {
                analyzeOperation(tx.v1().tx.sourceAccount, op);
            }
            break;
        default:
            mSkip = true;
        }
    }
};

// Finally, a test implementation of the Strife clustering algorithm.
// https://homes.cs.washington.edu/~suciu/guna-sigmod-2020-pdfa.pdf

using SpecialID = size_t;

struct RootData
{
    // This is set only if the cluster is special.
    std::optional<SpecialID> mSpecialID{std::nullopt};
    size_t mCount{1};
    std::shared_ptr<std::vector<TxID>> mTxs{nullptr};
    void
    merge(RootData& other)
    {
        if (mSpecialID)
        {
            releaseAssert(!other.mSpecialID);
        }
        else if (other.mSpecialID)
        {
            releaseAssert(!mSpecialID);
            mSpecialID.swap(other.mSpecialID);
        }
        mCount += other.mCount;
    }
};

struct ConcurrentPartitionAnalyzer
{
    // Constant parameters and inputs
    TransactionSet const& mTxs;
    DataDependencyAnalyzer const& mDDA;
    size_t const mK;
    double const mAlpha;
    size_t mNBins;

    // Data structures in the paper.
    BitSet mSpecial;
    SetPartition<RootData> mDataClusters;
    std::vector<std::vector<size_t>> mCount;
    std::vector<std::shared_ptr<std::vector<TxID>>> mTxClusters;
    std::vector<std::shared_ptr<std::vector<TxID>>> mTxBins;
    std::vector<TxID> mNoAccess;
    std::vector<TxID> mResidual;

    ConcurrentPartitionAnalyzer(TransactionSet const& txs,
                                DataDependencyAnalyzer const& dda, size_t k,
                                double alpha, size_t nbins)
        : mTxs(txs), mDDA(dda), mK(k), mAlpha(alpha), mNBins(nbins), mCount(k)
    {
        // Make one singleton data cluster for each data id.
        for (DataID _d = 0; _d < mDDA.keyToDataId.size(); ++_d)
        {
            mDataClusters.add();
        }
        for (auto& count : mCount)
        {
            // Allocate the special-cluster connection-count arrays.
            // These are only used in merge for indirectly-connected specials.
            count.resize(k);
        }
    }

    BitSet
    getAccessedClusters(TxID tx)
    {
        BitSet txData = mDDA.getAccessedData(tx);
        BitSet C;
        for (DataID data = 0; txData.nextSet(data); ++data)
        {
            C.set(mDataClusters.find(data));
        }
        // CLOG_INFO(Ledger, "txID {} accessed data {}", tx, C);
        return C;
    }

    void
    joinClusters(SetID& c, BitSet const& C)
    {
        releaseAssert(!C.empty());
        releaseAssert(C.get(c));
        for (SetID i = 0; C.nextSet(i); ++i)
        {
            mDataClusters.join(c, i);
        }
        c = mDataClusters.find(c);
    }

    // Steps from the paper.

    // Spot samples K transactions and creates a special cluster out of the data
    // for each sampled tx if that data is not yet in a special cluster.
    void
    spot()
    {
        for (SpecialID i = 0; i < mK; ++i)
        {
            TxID tx = rand_uniform<size_t>(0, mTxs.txs.size() - 1);
            BitSet C = getAccessedClusters(tx);
            CLOG_DEBUG(Ledger, "spot: tx {} accesses clusters {}", tx, C);
            if (C.empty())
            {
                continue;
            }
            BitSet S = C & mSpecial;
            CLOG_DEBUG(Ledger, "spot: tx {} accesses special clusters {}", tx,
                       S);
            if (S.empty())
            {
                SetID c{0};
                releaseAssert(C.nextSet(c));
                joinClusters(c, C);
                mSpecial.set(c);
                CLOG_DEBUG(
                    Ledger,
                    "spot: tx {} causing {} in cluster {} to become special",
                    tx, c, C);
                auto& cdata = mDataClusters.getRootData(c);
                cdata.mSpecialID.emplace(i);
            }
        }
    }

    // Fuse looks at all txs and clusters the tx's data into an existing special
    // cluster if it doesn't access more than one. If it does access more than
    // one, the pairwise connectivity of the specials that it accesses is
    // increased.
    void
    fuse()
    {
        for (TxID tx = 0; tx < mTxs.txs.size(); ++tx)
        {
            BitSet C = getAccessedClusters(tx);
            CLOG_DEBUG(Ledger, "fuse: tx {} accesses clusters {}", tx, C);
            if (C.empty())
            {
                continue;
            }
            BitSet S = C & mSpecial;
            CLOG_DEBUG(Ledger, "fuse: tx {} accesses special clusters {}", tx,
                       S);
            if (S.count() <= 1)
            {
                SetID c{0};
                if (S.empty())
                {
                    releaseAssert(C.nextSet(c));
                    CLOG_DEBUG(Ledger,
                               "fuse: tx {} clustering {} with non-special {}",
                               tx, C, c);
                    joinClusters(c, C);
                }
                else
                {
                    releaseAssert(S.nextSet(c));
                    auto saved_special = c;
                    CLOG_DEBUG(Ledger,
                               "fuse: tx {} clustering {} with special {}", tx,
                               C, c);
                    joinClusters(c, C);
                    // Might have transferred special from saved_special -> c
                    if (saved_special != c)
                    {
                        CLOG_DEBUG(Ledger,
                                   "fuse: tx {} transferred special-ness from "
                                   "{} to {}",
                                   tx, saved_special, c);
                        mSpecial.unset(saved_special);
                        mSpecial.set(c);
                    }
                }
                auto& cd = mDataClusters.getRootData(c);
                cd.mCount++;
                CLOG_DEBUG(Ledger, "fuse: tx {} bumped count on {} to {}", tx,
                           c, cd.mCount);
            }
            else
            {
                for (SetID c1 = 0; S.nextSet(c1); ++c1)
                {
                    auto const& c1d = mDataClusters.getRootData(c1);
                    releaseAssert(c1d.mSpecialID);
                    for (SetID c2 = 0; S.nextSet(c2); ++c2)
                    {
                        if (c1 == c2)
                        {
                            continue;
                        }
                        auto const& c2d = mDataClusters.getRootData(c2);
                        releaseAssert(c2d.mSpecialID);
                        mCount.at(*c1d.mSpecialID).at(*c2d.mSpecialID)++;
                    }
                }
            }
        }
    }

    // Merge relaxes the invariant of "no specials get merged" and begins
    // merging those that have a sufficiently high count of cross-cluster
    // access.
    void
    merge()
    {
        for (SetID c1 = 0; mSpecial.nextSet(c1); ++c1)
        {
            auto const& c1d = mDataClusters.getRootData(c1);
            for (SetID c2 = 0; mSpecial.nextSet(c2); ++c2)
            {
                if (c1 == c2)
                {
                    continue;
                }
                auto& c2d = mDataClusters.getRootData(c2);
                if (c1d.mSpecialID && c2d.mSpecialID)
                {
                    double n1 = mCount.at(*c1d.mSpecialID).at(*c2d.mSpecialID);
                    double n2 = c1d.mCount + c2d.mCount + n1;
                    if (n1 >= (mAlpha * n2))
                    {
                        // See paper section 3.1.4: the invariant that
                        // "no specials are merged" is relaxed in the
                        // merge step, so we (arbitrarily) forget the
                        // SpecialID of c2 here.
                        c2d.mSpecialID.reset();
                        mDataClusters.join(c1, c2);
                    }
                }
            }
        }
    }

    void
    allocate()
    {
        for (TxID tx = 0; tx < mTxs.txs.size(); ++tx)
        {
            BitSet C = getAccessedClusters(tx);
            switch (C.count())
            {
            case 0:
                mNoAccess.emplace_back(tx);
                break;

            case 1:
            {
                SetID c{0};
                releaseAssert(C.nextSet(c));
                auto& sd = mDataClusters.getRootData(c);
                if (!sd.mTxs)
                {
                    sd.mTxs = std::make_shared<std::vector<TxID>>();
                    mTxClusters.emplace_back(sd.mTxs);
                }
                sd.mTxs->emplace_back(tx);
            }
            break;

            default:
                mResidual.emplace_back(tx);
                break;
            }
        }
    }

    void
    binpack()
    {
        size_t nTxs = 0;
        for (auto const& c : mTxClusters)
        {
            nTxs += c->size();
        }
        std::sort(mTxClusters.begin(), mTxClusters.end(),
                  [](std::shared_ptr<std::vector<TxID>> const& a,
                     std::shared_ptr<std::vector<TxID>> const& b) {
                      return a->size() > b->size();
                  });
        size_t binsz = (nTxs + mNBins - 1) / mNBins;
        for (size_t i = 0; i < mNBins; ++i)
        {
            mTxBins.emplace_back(std::make_shared<std::vector<TxID>>());
        }
        std::shared_ptr<std::vector<TxID>> target;
        for (auto const& c : mTxClusters)
        {
            for (auto& b : mTxBins)
            {
                if (b->empty() || (b->size() + c->size() < binsz))
                {
                    if (!target || target->size() > b->size())
                    {
                        target = b;
                    }
                }
            }
            if (!target)
            {
                target = std::make_shared<std::vector<TxID>>();
                mTxBins.emplace_back(target);
            }
            target->insert(target->end(), c->begin(), c->end());
        }
    }

    void
    cluster()
    {
        spot();
        fuse();
        merge();
        allocate();

        // We add an additional final worst-fit binpacking phase here to merge
        // concurrent clusters, just to buid a static nbins multicore schedule.
        binpack();
    }
};

void
partitionTxSetForConcurrency(TransactionSet const& txset)
{
    // Parameters from the paper
    size_t k = 100;
    double alpha = 0.2;

    // Additional bin-packing parameters.
    size_t nbins = 8;

    if (getenv("CLUSTER_K"))
    {
        k = atoi(getenv("CLUSTER_K"));
    }

    if (getenv("CLUSTER_ALPHA"))
    {
        alpha = atof(getenv("CLUSTER_ALPHA"));
    }

    if (getenv("CLUSTER_BINS"))
    {
        nbins = atoi(getenv("CLUSTER_BINS"));
    }

    CLOG_INFO(Ledger,
              "Partitioning {} entry txset with k={}, alpha={}, nbins={}",
              txset.txs.size(), k, alpha, nbins);
    size_t n_skipped{0};
    DataDependencyAnalyzer dda(txset.txs.size());

    TxID txID{0};
    for (TransactionEnvelope const& tx : txset.txs)
    {
        SingleTxAnalyzer sta(dda, txID++);
        sta.analyzeTx(tx);
        if (sta.mSkip)
        {
            ++n_skipped;
        }
    }

    ConcurrentPartitionAnalyzer cpa(txset, dda, k, alpha, nbins);
    cpa.cluster();
    CLOG_INFO(Ledger,
              "Partitioned {} entry txset into {} concurrent clusters ({} "
              "bins), with {} "
              "residual, {} skipped, {} non-accessing",
              txset.txs.size(), cpa.mTxClusters.size(), cpa.mTxBins.size(),
              cpa.mResidual.size(), n_skipped, cpa.mNoAccess.size());

    BitSet roots = cpa.mDataClusters.getRoots();
    for (SetID r = 0; roots.nextSet(r); ++r)
    {
        CLOG_DEBUG(Ledger, "final cluster {} touched by {} txs", r,
                   cpa.mDataClusters.getRootData(r).mCount);
    }

    for (auto const& r : cpa.mResidual)
    {
        BitSet C = cpa.getAccessedClusters(r);
        CLOG_DEBUG(Ledger, "residual tx {} accesses clusters {}", r, C);
    }

    std::vector<BitSet> binData;
    std::string bins;
    for (auto const& cc : cpa.mTxBins)
    {
        BitSet cd;
        for (auto tx : *cc)
        {
            cd |= dda.getAccessedData(tx);
        }
        bins += fmt::format(" {}:{}", cc->size(), cd.count());
        binData.emplace_back(cd);
    }
    CLOG_INFO(Ledger, "bins (ntx:ndata):{}", bins);

    for (size_t i = 0; i < binData.size(); ++i)
    {
        BitSet ci = binData.at(i);
        for (size_t j = 0; j < binData.size(); ++j)
        {
            if (i == j)
            {
                continue;
            }
            BitSet cj = binData.at(j);
            BitSet isect = ci & cj;
            if (!isect.empty())
            {
                CLOG_ERROR(Ledger, "Bins {} and {} intersect: {} & {} = {}", i,
                           j, ci, cj, isect);
            }
        }
    }
}
}