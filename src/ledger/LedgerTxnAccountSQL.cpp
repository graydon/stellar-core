// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "crypto/SignerKey.h"
#include "database/Database.h"
#include "ledger/LedgerTxnImpl.h"
#include "util/Decoder.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "util/types.h"
#include "xdrpp/marshal.h"

namespace stellar
{

std::shared_ptr<LedgerEntry const>
LedgerTxnRoot::Impl::loadAccount(LedgerKey const& key) const
{
    std::string actIDStrKey = KeyUtils::toStrKey(key.account().accountID);

    std::string inflationDest, homeDomain, thresholds, signers;
    soci::indicator inflationDestInd, signersInd;
    Liabilities liabilities;
    soci::indicator buyingLiabilitiesInd, sellingLiabilitiesInd;

    LedgerEntry le;
    le.data.type(ACCOUNT);
    auto& account = le.data.account();

    auto prep =
        mDatabase.getPreparedStatement("SELECT balance, seqnum, numsubentries, "
                                       "inflationdest, homedomain, thresholds, "
                                       "flags, lastmodified, "
                                       "buyingliabilities, sellingliabilities, "
                                       "signers "
                                       "FROM accounts WHERE accountid=:v1");
    auto& st = prep.statement();
    st.exchange(soci::into(account.balance));
    st.exchange(soci::into(account.seqNum));
    st.exchange(soci::into(account.numSubEntries));
    st.exchange(soci::into(inflationDest, inflationDestInd));
    st.exchange(soci::into(homeDomain));
    st.exchange(soci::into(thresholds));
    st.exchange(soci::into(account.flags));
    st.exchange(soci::into(le.lastModifiedLedgerSeq));
    st.exchange(soci::into(liabilities.buying, buyingLiabilitiesInd));
    st.exchange(soci::into(liabilities.selling, sellingLiabilitiesInd));
    st.exchange(soci::into(signers, signersInd));
    st.exchange(soci::use(actIDStrKey));
    st.define_and_bind();
    {
        auto timer = mDatabase.getSelectTimer("account");
        st.execute(true);
    }
    if (!st.got_data())
    {
        return nullptr;
    }

    account.accountID = key.account().accountID;
    account.homeDomain = homeDomain;

    bn::decode_b64(thresholds.begin(), thresholds.end(),
                   account.thresholds.begin());

    if (inflationDestInd == soci::i_ok)
    {
        account.inflationDest.activate() =
            KeyUtils::fromStrKey<PublicKey>(inflationDest);
    }

    if (signersInd == soci::i_ok)
    {
        std::vector<uint8_t> signersOpaque;
        decoder::decode_b64(signers, signersOpaque);
        xdr::xdr_from_opaque(signersOpaque, account.signers);
        assert(std::adjacent_find(account.signers.begin(),
                                  account.signers.end(),
                                  [](Signer const& lhs, Signer const& rhs) {
                                      return !(lhs.key < rhs.key);
                                  }) == account.signers.end());
    }

    assert(buyingLiabilitiesInd == sellingLiabilitiesInd);
    if (buyingLiabilitiesInd == soci::i_ok)
    {
        account.ext.v(1);
        account.ext.v1().liabilities = liabilities;
    }

    return std::make_shared<LedgerEntry const>(std::move(le));
}

std::vector<InflationWinner>
LedgerTxnRoot::Impl::loadInflationWinners(size_t maxWinners,
                                          int64_t minBalance) const
{
    InflationWinner w;
    std::string inflationDest;

    auto prep = mDatabase.getPreparedStatement(
        "SELECT sum(balance) AS votes, inflationdest"
        " FROM accounts WHERE inflationdest IS NOT NULL"
        " AND balance >= 1000000000 GROUP BY inflationdest"
        " ORDER BY votes DESC, inflationdest DESC LIMIT :lim");
    auto& st = prep.statement();
    st.exchange(soci::into(w.votes));
    st.exchange(soci::into(inflationDest));
    st.exchange(soci::use(maxWinners));
    st.define_and_bind();
    st.execute(true);

    std::vector<InflationWinner> winners;
    while (st.got_data())
    {
        w.accountID = KeyUtils::fromStrKey<PublicKey>(inflationDest);
        if (w.votes < minBalance)
        {
            break;
        }
        winners.push_back(w);
        st.fetch();
    }
    return winners;
}

void
LedgerTxnRoot::Impl::writeSignersTableIntoAccountsTable()
{
    throwIfChild();
    soci::transaction sqlTx(mDatabase.getSession());

    CLOG(INFO, "Ledger") << "Loading all signers from signers table";
    std::map<std::string, xdr::xvector<Signer, 20>> signersByAccount;

    {
        std::string accountIDStrKey, pubKey;
        Signer signer;

        auto prep = mDatabase.getPreparedStatement(
            "SELECT accountid, publickey, weight FROM signers");
        auto& st = prep.statement();
        st.exchange(soci::into(accountIDStrKey));
        st.exchange(soci::into(pubKey));
        st.exchange(soci::into(signer.weight));
        st.define_and_bind();
        {
            auto timer = mDatabase.getSelectTimer("signer");
            st.execute(true);
        }
        while (st.got_data())
        {
            signer.key = KeyUtils::fromStrKey<SignerKey>(pubKey);
            signersByAccount[accountIDStrKey].emplace_back(signer);
            st.fetch();
        }
    }

    size_t numAccountsUpdated = 0;
    for (auto const& kv : signersByAccount)
    {
        assert(std::adjacent_find(kv.second.begin(), kv.second.end(),
                                  [](Signer const& lhs, Signer const& rhs) {
                                      return !(lhs.key < rhs.key);
                                  }) == kv.second.end());
        std::string signers(decoder::encode_b64(xdr::xdr_to_opaque(kv.second)));

        auto prep = mDatabase.getPreparedStatement(
            "UPDATE accounts SET signers = :v1 WHERE accountID = :id");
        auto& st = prep.statement();
        st.exchange(soci::use(signers, "v1"));
        st.exchange(soci::use(kv.first, "id"));
        st.define_and_bind();
        st.execute(true);
        if (st.get_affected_rows() != 1)
        {
            throw std::runtime_error("Could not update data in SQL");
        }

        if ((++numAccountsUpdated & 0xfff) == 0xfff ||
            (numAccountsUpdated == signersByAccount.size()))
        {
            CLOG(INFO, "Ledger")
                << "Wrote signers for " << numAccountsUpdated << " accounts";
        }
    }

    sqlTx.commit();

    // Clearing the cache does not throw
    mEntryCache.clear();
    mBestOffersCache.clear();
}

void
LedgerTxnRoot::Impl::insertOrUpdateAccount(LedgerEntry const& entry,
                                           bool isInsert)
{
    auto const& account = entry.data.account();
    std::string actIDStrKey = KeyUtils::toStrKey(account.accountID);

    soci::indicator inflation_ind = soci::i_null;
    std::string inflationDestStrKey;
    if (account.inflationDest)
    {
        inflationDestStrKey = KeyUtils::toStrKey(*account.inflationDest);
        inflation_ind = soci::i_ok;
    }

    Liabilities liabilities;
    soci::indicator liabilitiesInd = soci::i_null;
    if (account.ext.v() == 1)
    {
        liabilities = account.ext.v1().liabilities;
        liabilitiesInd = soci::i_ok;
    }

    std::string thresholds(decoder::encode_b64(account.thresholds));
    std::string homeDomain(account.homeDomain);

    soci::indicator signersInd = soci::i_null;
    std::string signers;
    if (!account.signers.empty())
    {
        signers = decoder::encode_b64(xdr::xdr_to_opaque(account.signers));
        signersInd = soci::i_ok;
    }

    std::string sql;
    if (isInsert)
    {
        sql = "INSERT INTO accounts ( accountid, balance, seqnum, "
              "numsubentries, inflationdest, homedomain, thresholds, flags, "
              "lastmodified, buyingliabilities, sellingliabilities, signers ) "
              "VALUES ( :id, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, "
              ":v10, :v11 )";
    }
    else
    {
        sql = "UPDATE accounts SET balance = :v1, seqnum = :v2, "
              "numsubentries = :v3, inflationdest = :v4, homedomain = :v5, "
              "thresholds = :v6, flags = :v7, lastmodified = :v8, "
              "buyingliabilities = :v9, sellingliabilities = :v10, "
              "signers = :v11 WHERE accountid = :id";
    }
    auto prep = mDatabase.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    int32_t signedNumSubEntries = unsignedToSigned(account.numSubEntries);
    int32_t signedFlags = unsignedToSigned(account.flags);
    st.exchange(soci::use(actIDStrKey, "id"));
    st.exchange(soci::use(account.balance, "v1"));
    st.exchange(soci::use(account.seqNum, "v2"));
    st.exchange(soci::use(signedNumSubEntries, "v3"));
    st.exchange(soci::use(inflationDestStrKey, inflation_ind, "v4"));
    st.exchange(soci::use(homeDomain, "v5"));
    st.exchange(soci::use(thresholds, "v6"));
    st.exchange(soci::use(signedFlags, "v7"));
    st.exchange(soci::use(entry.lastModifiedLedgerSeq, "v8"));
    st.exchange(soci::use(liabilities.buying, liabilitiesInd, "v9"));
    st.exchange(soci::use(liabilities.selling, liabilitiesInd, "v10"));
    st.exchange(soci::use(signers, signersInd, "v11"));
    st.define_and_bind();
    {
        auto timer = isInsert ? mDatabase.getInsertTimer("account")
                              : mDatabase.getUpdateTimer("account");
        st.execute(true);
    }
    if (st.get_affected_rows() != 1)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

void
LedgerTxnRoot::Impl::deleteAccount(LedgerKey const& key)
{
    std::string actIDStrKey = KeyUtils::toStrKey(key.account().accountID);

    {
        auto prep = mDatabase.getPreparedStatement(
            "DELETE FROM accounts WHERE accountid= :v1");
        auto& st = prep.statement();
        st.exchange(soci::use(actIDStrKey));
        st.define_and_bind();
        {
            auto timer = mDatabase.getDeleteTimer("account");
            st.execute(true);
        }
        if (st.get_affected_rows() != 1 &&
            mConsistency == LedgerTxnConsistency::EXACT)
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }
}

static void
sociGenericBulkUpsertAccounts(Database& DB,
                              std::vector<std::string> const& accountIDs,
                              std::vector<int64_t> const& balances,
                              std::vector<int64_t> const& seqNums,
                              std::vector<int32_t> const& subEntryNums,
                              std::vector<std::string> const& inflationDests,
                              std::vector<soci::indicator>& inflationDestInds,
                              std::vector<int32_t> const& flags,
                              std::vector<std::string> const& homeDomains,
                              std::vector<std::string> const& thresholds,
                              std::vector<std::string> const& signers,
                              std::vector<soci::indicator>& signerInds,
                              std::vector<int32_t> const& lastModifieds,
                              std::vector<int64_t> const& buyingLiabilities,
                              std::vector<int64_t> const& sellingLiabilities,
                              std::vector<soci::indicator>& liabilitiesInds)
{
    std::string sql =
        "INSERT INTO accounts ( "
        "accountid, balance, seqnum, numsubentries, inflationdest,"
        "homedomain, thresholds, signers, flags, lastmodified, "
        "buyingliabilities, sellingliabilities "
        ") VALUES ( "
        ":id, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11 "
        ") ON CONFLICT (accountid) DO UPDATE SET "
        "balance = excluded.balance, "
        "seqnum = excluded.seqnum, "
        "numsubentries = excluded.numsubentries, "
        "inflationdest = excluded.inflationdest, "
        "homedomain = excluded.homedomain, "
        "thresholds = excluded.thresholds, "
        "signers = excluded.signers, "
        "flags = excluded.flags, "
        "lastmodified = excluded.lastmodified, "
        "buyingliabilities = excluded.buyingliabilities, "
        "sellingliabilities = excluded.sellingliabilities";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(accountIDs, "id"));
    st.exchange(soci::use(balances, "v1"));
    st.exchange(soci::use(seqNums, "v2"));
    st.exchange(soci::use(subEntryNums, "v3"));
    st.exchange(soci::use(inflationDests, inflationDestInds, "v4"));
    st.exchange(soci::use(homeDomains, "v5"));
    st.exchange(soci::use(thresholds, "v6"));
    st.exchange(soci::use(signers, signerInds, "v7"));
    st.exchange(soci::use(flags, "v8"));
    st.exchange(soci::use(lastModifieds, "v9"));
    st.exchange(soci::use(buyingLiabilities, liabilitiesInds, "v10"));
    st.exchange(soci::use(sellingLiabilities, liabilitiesInds, "v11"));
    st.define_and_bind();
    {
        auto timer = DB.getUpsertTimer("account");
        st.execute(true);
    }
    if (st.get_affected_rows() != accountIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sociGenericBulkDeleteAccounts(Database& DB, LedgerTxnConsistency cons,
                              std::vector<std::string> const& accountIDs)
{
    std::string sql = "DELETE FROM accounts WHERE accountid = :id";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(accountIDs, "id"));
    st.define_and_bind();
    {
        auto timer = DB.getDeleteTimer("account");
        st.execute(true);
    }
    if (st.get_affected_rows() != accountIDs.size() &&
        cons == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

#ifdef USE_POSTGRES
static void
postgresSpecificBulkUpsertAccounts(
    Database& DB, std::vector<std::string> const& accountIDs,
    std::vector<int64_t> const& balances, std::vector<int64_t> const& seqNums,
    std::vector<int32_t> const& subEntryNums,
    std::vector<std::string> const& inflationDests,
    std::vector<soci::indicator>& inflationDestInds,
    std::vector<int32_t> const& flags,
    std::vector<std::string> const& homeDomains,
    std::vector<std::string> const& thresholds,
    std::vector<std::string> const& signers,
    std::vector<soci::indicator>& signerInds,
    std::vector<int32_t> const& lastModifieds,
    std::vector<int64_t> const& buyingLiabilities,
    std::vector<int64_t> const& sellingLiabilities,
    std::vector<soci::indicator>& liabilitiesInds)
{

    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;

    std::string strAccountIDs, strBalances, strSeqNums, strSubEntryNums,
        strInflationDests, strFlags, strHomeDomains, strThresholds, strSigners,
        strLastModifieds, strBuyingLiabilities, strSellingLiabilities;

    marshalToPGArray(conn, strAccountIDs, accountIDs);
    marshalToPGArray(conn, strBalances, balances);
    marshalToPGArray(conn, strSeqNums, seqNums);
    marshalToPGArray(conn, strSubEntryNums, subEntryNums);
    marshalToPGArray(conn, strInflationDests, inflationDests,
                     &inflationDestInds);
    marshalToPGArray(conn, strFlags, flags);
    marshalToPGArray(conn, strHomeDomains, homeDomains);
    marshalToPGArray(conn, strThresholds, thresholds);
    marshalToPGArray(conn, strSigners, signers, &signerInds);
    marshalToPGArray(conn, strLastModifieds, lastModifieds);
    marshalToPGArray(conn, strBuyingLiabilities, buyingLiabilities,
                     &liabilitiesInds);
    marshalToPGArray(conn, strSellingLiabilities, sellingLiabilities,
                     &liabilitiesInds);

    std::string sql =
        "WITH r AS (SELECT "
        "unnest(:ids::TEXT[]), "
        "unnest(:balances::BIGINT[]), "
        "unnest(:seqnums::BIGINT[]), "
        "unnest(:numsubentries::INT[]), "
        "unnest(:inflationdests::TEXT[]), "
        "unnest(:homedomains::TEXT[]), "
        "unnest(:thresholds::TEXT[]), "
        "unnest(:signers::TEXT[]), "
        "unnest(:flags::INT[]), "
        "unnest(:lastmodifieds::INT[]), "
        "unnest(:buyingliabilities::BIGINT[]), "
        "unnest(:sellingliabilities::BIGINT[]) "
        ")"
        "INSERT INTO accounts ( "
        "accountid, balance, seqnum, "
        "numsubentries, inflationdest, homedomain, thresholds, signers, "
        "flags, lastmodified, buyingliabilities, sellingliabilities "
        ") SELECT * FROM r "
        "ON CONFLICT (accountid) DO UPDATE SET "
        "balance = excluded.balance, "
        "seqnum = excluded.seqnum, "
        "numsubentries = excluded.numsubentries, "
        "inflationdest = excluded.inflationdest, "
        "homedomain = excluded.homedomain, "
        "thresholds = excluded.thresholds, "
        "signers = excluded.signers, "
        "flags = excluded.flags, "
        "lastmodified = excluded.lastmodified, "
        "buyingliabilities = excluded.buyingliabilities, "
        "sellingliabilities = excluded.sellingliabilities";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strAccountIDs, "ids"));
    st.exchange(soci::use(strBalances, "balances"));
    st.exchange(soci::use(strSeqNums, "seqnums"));
    st.exchange(soci::use(strSubEntryNums, "numsubentries"));
    st.exchange(soci::use(strInflationDests, "inflationdests"));
    st.exchange(soci::use(strHomeDomains, "homedomains"));
    st.exchange(soci::use(strThresholds, "thresholds"));
    st.exchange(soci::use(strSigners, "signers"));
    st.exchange(soci::use(strFlags, "flags"));
    st.exchange(soci::use(strLastModifieds, "lastmodifieds"));
    st.exchange(soci::use(strBuyingLiabilities, "buyingliabilities"));
    st.exchange(soci::use(strSellingLiabilities, "sellingliabilities"));
    st.define_and_bind();
    {
        auto timer = DB.getUpsertTimer("account");
        st.execute(true);
    }
    if (st.get_affected_rows() != accountIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
postgresSpecificBulkDeleteAccounts(Database& DB, LedgerTxnConsistency cons,
                                   std::vector<std::string> const& accountIDs)
{
    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;
    std::string strAccountIDs;
    marshalToPGArray(conn, strAccountIDs, accountIDs);
    std::string sql =
        "WITH r AS (SELECT unnest(:ids::TEXT[])) "
        "DELETE FROM accounts WHERE accountid IN (SELECT * FROM r)";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strAccountIDs, "ids"));
    st.define_and_bind();
    {
        auto timer = DB.getDeleteTimer("account");
        st.execute(true);
    }
    if (st.get_affected_rows() != accountIDs.size() &&
        cons == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}
#endif

void
LedgerTxnRoot::Impl::bulkUpsertAccounts(
    std::vector<EntryIterator> const& entries)
{
    std::vector<std::string> accountIDs;
    std::vector<int64_t> balances;
    std::vector<int64_t> seqNums;
    std::vector<int32_t> subEntryNums;
    std::vector<std::string> inflationDests;
    std::vector<soci::indicator> inflationDestInds;
    std::vector<int32_t> flags;
    std::vector<std::string> homeDomains;
    std::vector<std::string> thresholds;
    std::vector<std::string> signers;
    std::vector<soci::indicator> signerInds;
    std::vector<int32_t> lastModifieds;
    std::vector<int64_t> buyingLiabilities;
    std::vector<int64_t> sellingLiabilities;
    std::vector<soci::indicator> liabilitiesInds;

    accountIDs.reserve(entries.size());
    balances.reserve(entries.size());
    seqNums.reserve(entries.size());
    subEntryNums.reserve(entries.size());
    inflationDests.reserve(entries.size());
    inflationDestInds.reserve(entries.size());
    flags.reserve(entries.size());
    homeDomains.reserve(entries.size());
    thresholds.reserve(entries.size());
    signers.reserve(entries.size());
    signerInds.reserve(entries.size());
    lastModifieds.reserve(entries.size());
    buyingLiabilities.reserve(entries.size());
    sellingLiabilities.reserve(entries.size());
    liabilitiesInds.reserve(entries.size());

    for (auto const& e : entries)
    {
        assert(e.entryExists());
        assert(e.entry().data.type() == ACCOUNT);
        auto const& account = e.entry().data.account();
        accountIDs.push_back(KeyUtils::toStrKey(account.accountID));
        balances.push_back(account.balance);
        seqNums.push_back(account.seqNum);
        subEntryNums.push_back(unsignedToSigned(account.numSubEntries));

        if (account.inflationDest)
        {
            inflationDests.push_back(
                KeyUtils::toStrKey(*account.inflationDest));
            inflationDestInds.push_back(soci::i_ok);
        }
        else
        {
            inflationDests.push_back("");
            inflationDestInds.push_back(soci::i_null);
        }
        flags.push_back(unsignedToSigned(account.flags));
        homeDomains.push_back(account.homeDomain);
        thresholds.push_back(decoder::encode_b64(account.thresholds));
        if (account.signers.empty())
        {
            signers.push_back("");
            signerInds.push_back(soci::i_null);
        }
        else
        {
            signers.push_back(
                decoder::encode_b64(xdr::xdr_to_opaque(account.signers)));
            signerInds.push_back(soci::i_ok);
        }
        lastModifieds.push_back(
            unsignedToSigned(e.entry().lastModifiedLedgerSeq));

        if (account.ext.v() >= 1)
        {
            buyingLiabilities.push_back(account.ext.v1().liabilities.buying);
            sellingLiabilities.push_back(account.ext.v1().liabilities.selling);
            liabilitiesInds.push_back(soci::i_ok);
        }
        else
        {
            buyingLiabilities.push_back(0);
            sellingLiabilities.push_back(0);
            liabilitiesInds.push_back(soci::i_null);
        }

        dropFromEntryCacheIfPresent(e.key());
    }

    // At the moment we only have two flavors of database support, this
    // condition 2-way split will need to change if we support more.
    if (mDatabase.isSqlite())
    {
        sociGenericBulkUpsertAccounts(
            mDatabase, accountIDs, balances, seqNums, subEntryNums,
            inflationDests, inflationDestInds, flags, homeDomains, thresholds,
            signers, signerInds, lastModifieds, buyingLiabilities,
            sellingLiabilities, liabilitiesInds);
    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkUpsertAccounts(
            mDatabase, accountIDs, balances, seqNums, subEntryNums,
            inflationDests, inflationDestInds, flags, homeDomains, thresholds,
            signers, signerInds, lastModifieds, buyingLiabilities,
            sellingLiabilities, liabilitiesInds);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::bulkDeleteAccounts(
    std::vector<EntryIterator> const& entries)
{
    std::vector<std::string> accountIDs;
    for (auto const& e : entries)
    {
        assert(!e.entryExists());
        assert(e.key().type() == ACCOUNT);
        auto const& account = e.key().account();
        accountIDs.push_back(KeyUtils::toStrKey(account.accountID));
        dropFromEntryCacheIfPresent(e.key());
    }
    // At the moment we only have two flavors of database support, this
    // condition 2-way split will need to change if we support more.
    if (mDatabase.isSqlite())
    {
        sociGenericBulkDeleteAccounts(mDatabase, mConsistency, accountIDs);
    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkDeleteAccounts(mDatabase, mConsistency, accountIDs);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::dropAccounts()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffersCache.clear();

    mDatabase.getSession() << "DROP TABLE IF EXISTS accounts;";
    mDatabase.getSession() << "DROP TABLE IF EXISTS signers;";

    mDatabase.getSession()
        << "CREATE TABLE accounts"
           "("
           "accountid       VARCHAR(56)  PRIMARY KEY,"
           "balance         BIGINT       NOT NULL CHECK (balance >= 0),"
           "seqnum          BIGINT       NOT NULL,"
           "numsubentries   INT          NOT NULL CHECK (numsubentries >= 0),"
           "inflationdest   VARCHAR(56),"
           "homedomain      VARCHAR(32)  NOT NULL,"
           "thresholds      TEXT         NOT NULL,"
           "flags           INT          NOT NULL,"
           "lastmodified    INT          NOT NULL"
           ");";
    mDatabase.getSession() << "CREATE TABLE signers"
                              "("
                              "accountid       VARCHAR(56) NOT NULL,"
                              "publickey       VARCHAR(56) NOT NULL,"
                              "weight          INT         NOT NULL,"
                              "PRIMARY KEY (accountid, publickey)"
                              ");";
    mDatabase.getSession()
        << "CREATE INDEX signersaccount ON signers (accountid)";
    mDatabase.getSession()
        << "CREATE INDEX accountbalances ON accounts (balance) WHERE "
           "balance >= 1000000000";
}
}
