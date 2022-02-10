#include "ledger/ConcurrentTxPartition.h"
#include "ledger/LedgerTxn.h"
#include "transactions/TransactionUtils.h"
#include "util/BitSet.h"
#include "util/Logging.h"
#include "xdr/Stellar-ledger-entries.h"
#include "xdr/Stellar-transaction.h"
#include "xdr/Stellar-types.h"
#include <optional>
#include <variant>

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

// This is just a test implementation of the Strife clustering algorithm.
struct ConcurrentPartitionAnalyzer
{
    std::unordered_map<DataKey, DataID> keyToDataId;
    DataID
    getID(DataKey const& k)
    {
        DataID next = keyToDataId.size();
        auto pair = keyToDataId.emplace(k, next);
        return pair.first->second;
    }
    TxID mNextTx{0};
    std::vector<BitSet> mReadSets;
    std::vector<BitSet> mWriteSets;
    void
    recordDependency(TxID txID, DataKey const& dep, AccessMode mode)
    {
        std::vector<BitSet>& sets =
            (mode == AccessMode::READ) ? mReadSets : mWriteSets;
        while (sets.size() < txID + 1)
        {
            sets.emplace_back(BitSet());
        }
        DataID data = getID(dep);
        CLOG_DEBUG(Ledger, "Tx {} {}-depends on data {}", txID,
                   (mode == AccessMode::READ) ? "read" : "write", data);
        sets.at(txID).set(data);
    }
};

struct SingleTxAnalyzer
{
    ConcurrentPartitionAnalyzer& mCPA;
    TxID mTxID;

    // FIXME: for this generation we're just experimenting so we can skip cases
    // we don't want to analyze and we'll just filter them out of the analysis.
    bool mSkip{false};

    SingleTxAnalyzer(ConcurrentPartitionAnalyzer& cpa)
        : mCPA(cpa), mTxID(mCPA.mNextTx++)
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
        mCPA.recordDependency(mTxID, k, mode);
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

void
partitionTxSetForConcurrency(TransactionSet const& txset)
{
    CLOG_INFO(Ledger, "Partitioning {} entry txset", txset.txs.size());
    size_t n_skipped{0};
    ConcurrentPartitionAnalyzer cpa;

    for (TransactionEnvelope const& tx : txset.txs)
    {
        SingleTxAnalyzer sta(cpa);
        sta.analyzeTx(tx);
        if (sta.mSkip)
        {
            ++n_skipped;
        }
    }

    CLOG_INFO(Ledger, "Partitioned {} entry txset, skipped {}",
              txset.txs.size(), n_skipped);
}
}