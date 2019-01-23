// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "database/Database.h"
#include "ledger/LedgerTxnImpl.h"
#include "util/XDROperators.h"
#include "util/types.h"
#include <soci-sqlite3.h>

namespace stellar
{

static void
getTrustLineStrings(AccountID const& accountID, Asset const& asset,
                    std::string& accountIDStr, std::string& issuerStr,
                    std::string& assetCodeStr)
{
    if (asset.type() == ASSET_TYPE_NATIVE)
    {
        throw std::runtime_error("XLM TrustLine?");
    }
    else if (accountID == getIssuer(asset))
    {
        throw std::runtime_error("TrustLine accountID is issuer");
    }

    accountIDStr = KeyUtils::toStrKey(accountID);
    if (asset.type() == ASSET_TYPE_CREDIT_ALPHANUM4)
    {
        assetCodeToStr(asset.alphaNum4().assetCode, assetCodeStr);
        issuerStr = KeyUtils::toStrKey(asset.alphaNum4().issuer);
    }
    else if (asset.type() == ASSET_TYPE_CREDIT_ALPHANUM12)
    {
        assetCodeToStr(asset.alphaNum12().assetCode, assetCodeStr);
        issuerStr = KeyUtils::toStrKey(asset.alphaNum12().issuer);
    }
    else
    {
        throw std::runtime_error("Unknown asset type");
    }
}

std::shared_ptr<LedgerEntry const>
LedgerTxnRoot::Impl::loadTrustLine(LedgerKey const& key) const
{
    std::string accountIDStr, issuerStr, assetStr;
    getTrustLineStrings(key.trustLine().accountID, key.trustLine().asset,
                        accountIDStr, issuerStr, assetStr);

    Liabilities liabilities;
    soci::indicator buyingLiabilitiesInd, sellingLiabilitiesInd;

    LedgerEntry le;
    le.data.type(TRUSTLINE);
    TrustLineEntry& tl = le.data.trustLine();

    auto prep = mDatabase.getPreparedStatement(
        "SELECT tlimit, balance, flags, lastmodified, buyingliabilities, "
        "sellingliabilities FROM trustlines "
        "WHERE accountid= :id AND issuer= :issuer AND assetcode= :asset");
    auto& st = prep.statement();
    st.exchange(soci::into(tl.limit));
    st.exchange(soci::into(tl.balance));
    st.exchange(soci::into(tl.flags));
    st.exchange(soci::into(le.lastModifiedLedgerSeq));
    st.exchange(soci::into(liabilities.buying, buyingLiabilitiesInd));
    st.exchange(soci::into(liabilities.selling, sellingLiabilitiesInd));
    st.exchange(soci::use(accountIDStr));
    st.exchange(soci::use(issuerStr));
    st.exchange(soci::use(assetStr));
    st.define_and_bind();
    {
        auto timer = mDatabase.getSelectTimer("trust");
        st.execute(true);
    }
    if (!st.got_data())
    {
        return nullptr;
    }

    tl.accountID = key.trustLine().accountID;
    tl.asset = key.trustLine().asset;

    assert(buyingLiabilitiesInd == sellingLiabilitiesInd);
    if (buyingLiabilitiesInd == soci::i_ok)
    {
        tl.ext.v(1);
        tl.ext.v1().liabilities = liabilities;
    }

    return std::make_shared<LedgerEntry>(std::move(le));
}

void
LedgerTxnRoot::Impl::insertOrUpdateTrustLine(LedgerEntry const& entry,
                                             bool isInsert)
{
    auto const& tl = entry.data.trustLine();

    std::string accountIDStr, issuerStr, assetCodeStr;
    getTrustLineStrings(tl.accountID, tl.asset, accountIDStr, issuerStr,
                        assetCodeStr);

    unsigned int assetType = tl.asset.type();
    Liabilities liabilities;
    soci::indicator liabilitiesInd = soci::i_null;
    if (tl.ext.v() == 1)
    {
        liabilities = tl.ext.v1().liabilities;
        liabilitiesInd = soci::i_ok;
    }

    std::string sql;
    if (isInsert)
    {
        sql = "INSERT INTO trustlines "
              "(accountid, assettype, issuer, assetcode, balance, tlimit, "
              "flags, lastmodified, buyingliabilities, sellingliabilities) "
              "VALUES (:id, :at, :iss, :ac, :b, :tl, :f, :lm, :bl, :sl)";
    }
    else
    {
        sql = "UPDATE trustlines "
              "SET balance=:b, tlimit=:tl, flags=:f, lastmodified=:lm, "
              "buyingliabilities=:bl, sellingliabilities=:sl "
              "WHERE accountid=:id AND issuer=:iss AND assetcode=:ac";
    }
    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    int32_t signedLastModified = unsignedToSigned(entry.lastModifiedLedgerSeq);
    int32_t signedFlags = unsignedToSigned(tl.flags);
    st.exchange(soci::use(accountIDStr, "id"));
    if (isInsert)
    {
        st.exchange(soci::use(assetType, "at"));
    }
    st.exchange(soci::use(issuerStr, "iss"));
    st.exchange(soci::use(assetCodeStr, "ac"));
    st.exchange(soci::use(tl.balance, "b"));
    st.exchange(soci::use(tl.limit, "tl"));
    st.exchange(soci::use(signedFlags, "f"));
    st.exchange(soci::use(signedLastModified, "lm"));
    st.exchange(soci::use(liabilities.buying, liabilitiesInd, "bl"));
    st.exchange(soci::use(liabilities.selling, liabilitiesInd, "sl"));
    st.define_and_bind();
    {
        auto timer = isInsert ? mDatabase.getInsertTimer("trust")
                              : mDatabase.getUpdateTimer("trust");
        st.execute(true);
    }
    if (st.get_affected_rows() != 1)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

void
LedgerTxnRoot::Impl::deleteTrustLine(LedgerKey const& key)
{
    auto const& tl = key.trustLine();

    std::string accountIDStr, issuerStr, assetCodeStr;
    getTrustLineStrings(tl.accountID, tl.asset, accountIDStr, issuerStr,
                        assetCodeStr);

    auto prep = mDatabase.getPreparedStatement(
        "DELETE FROM trustlines "
        "WHERE accountid=:v1 AND issuer=:v2 AND assetcode=:v3");
    auto& st = prep.statement();
    st.exchange(soci::use(accountIDStr));
    st.exchange(soci::use(issuerStr));
    st.exchange(soci::use(assetCodeStr));
    st.define_and_bind();
    {
        auto timer = mDatabase.getDeleteTimer("trust");
        st.execute(true);
    }
    if (st.get_affected_rows() != 1 &&
        mConsistency == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sqliteSpecificBulkUpsertTrustLines(Database& DB,
                                   std::vector<std::string> const& accountIDs,
                                   std::vector<int32_t> const& assetTypes,
                                   std::vector<std::string> const& issuers,
                                   std::vector<std::string> const& assetCodes,
                                   std::vector<int64_t> const& tlimits,
                                   std::vector<int64_t> const& balances,
                                   std::vector<int32_t> const& flags,
                                   std::vector<int32_t> const& lastModifieds,
                                   std::vector<int64_t> const& buyingLiabilities,
                                   std::vector<int64_t> const& sellingLiabilities,
                                   std::vector<soci::indicator>& liabilitiesInds)
{
    std::vector<const char*> cStrAccountIDs, cStrIssuers, cStrAssetCodes;
    marshalToSqliteArray(cStrAccountIDs, accountIDs);
    marshalToSqliteArray(cStrIssuers, issuers);
    marshalToSqliteArray(cStrAssetCodes, assetCodes);

    std::vector<const int64_t *> buyingLiabilityPtrs, sellingLiabilityPtrs;
    marshalToSqliteArray(buyingLiabilityPtrs, buyingLiabilities, liabilitiesInds);
    marshalToSqliteArray(sellingLiabilityPtrs, sellingLiabilities, liabilitiesInds);

    std::string sqlJoin =
        "SELECT v1.value, v2.value, v3.value, v4.value, v5.value, "
        "v6.value, v7.value, v8.value, v9.value, v10.value "
        " FROM "
        "           (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v1 "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32') ORDER BY rowid) AS v2 ON v1.rowid = v2.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v3 ON v1.rowid = v3.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v4 ON v1.rowid = v4.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int64') ORDER BY rowid) AS v5 ON v1.rowid = v5.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int64') ORDER BY rowid) AS v6 ON v1.rowid = v6.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32') ORDER BY rowid) AS v7 ON v1.rowid = v7.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32') ORDER BY rowid) AS v8 ON v1.rowid = v8.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int64*') ORDER BY rowid) AS v9 ON v1.rowid = v9.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int64*') ORDER BY rowid) AS v10 ON v1.rowid = v10.rowid ";

    std::string sql =
        "WITH r AS ( " + sqlJoin + " ) "
        "INSERT INTO trustlines ( "
        "accountid, assettype, issuer, assetcode,"
        "tlimit, balance, flags, lastmodified, "
        "buyingliabilities, sellingliabilities "
        ") SELECT * FROM r "

        // NB: this 'WHERE true' is the official way to resolve a
        // parsing ambiguity wrt. the following 'ON' token. Really.
        // See: https://www.sqlite.org/lang_insert.html
        " WHERE true "

        "ON CONFLICT (accountid, issuer, assetcode) DO UPDATE SET "
        "assettype = excluded.assettype, "
        "tlimit = excluded.tlimit, "
        "balance = excluded.balance, "
        "flags = excluded.flags, "
        "lastmodified = excluded.lastmodified, "
        "buyingliabilities = excluded.buyingliabilities, "
        "sellingliabilities = excluded.sellingliabilities ";

    auto prep = DB.getPreparedStatement(sql);
    auto sqliteStatement = dynamic_cast<soci::sqlite3_statement_backend*>(prep.statement().get_backend());
    auto st = sqliteStatement->stmt_;
    sqlite3_reset(st);
    sqlite3_bind_pointer(st, 1, cStrAccountIDs.data(), "carray", 0);
    sqlite3_bind_int(st, 2, cStrAccountIDs.size());
    sqlite3_bind_pointer(st, 3, const_cast<int32_t*>(assetTypes.data()), "carray", 0);
    sqlite3_bind_int(st, 4, assetTypes.size());
    sqlite3_bind_pointer(st, 5, cStrIssuers.data(), "carray", 0);
    sqlite3_bind_int(st, 6, cStrIssuers.size());
    sqlite3_bind_pointer(st, 7, cStrAssetCodes.data(), "carray", 0);
    sqlite3_bind_int(st, 8, cStrAssetCodes.size());
    sqlite3_bind_pointer(st, 9, const_cast<int64_t*>(tlimits.data()), "carray", 0);
    sqlite3_bind_int(st, 10, tlimits.size());
    sqlite3_bind_pointer(st, 11, const_cast<int64_t*>(balances.data()), "carray", 0);
    sqlite3_bind_int(st, 12, balances.size());
    sqlite3_bind_pointer(st, 13, const_cast<int32_t*>(flags.data()), "carray", 0);
    sqlite3_bind_int(st, 14, flags.size());
    sqlite3_bind_pointer(st, 15, const_cast<int32_t*>(lastModifieds.data()), "carray", 0);
    sqlite3_bind_int(st, 16, lastModifieds.size());
    sqlite3_bind_pointer(st, 17, buyingLiabilityPtrs.data(), "carray", 0);
    sqlite3_bind_int(st, 18, buyingLiabilityPtrs.size());
    sqlite3_bind_pointer(st, 19, sellingLiabilityPtrs.data(), "carray", 0);
    sqlite3_bind_int(st, 20, sellingLiabilityPtrs.size());

    {
        auto timer = DB.getUpsertTimer("trustline");
        if (sqlite3_step(st) != SQLITE_DONE)
        {
            throw std::runtime_error("SQLite failure");
        }
    }

    soci::session& session = DB.getSession();
    auto sqlite =
        dynamic_cast<soci::sqlite3_session_backend*>(session.get_backend());
    if (sqlite3_changes(sqlite->conn_) != accountIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sqliteSpecificBulkDeleteTrustLines(Database& DB, LedgerTxnConsistency cons,
                                   std::vector<std::string> const& accountIDs,
                                   std::vector<std::string> const& issuers,
                                   std::vector<std::string> const& assetCodes)
{
    std::vector<const char*> cStrAccountIDs, cStrIssuers, cStrAssetCodes;
    marshalToSqliteArray(cStrAccountIDs, accountIDs);
    marshalToSqliteArray(cStrIssuers, issuers);
    marshalToSqliteArray(cStrAssetCodes, assetCodes);

    std::string sqlJoin =
        "SELECT v1.value, v2.value, v3.value "
        " FROM "
        "           (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v1 "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v2 ON v1.rowid = v2.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v3 ON v1.rowid = v3.rowid ";
    std::string sql = "WITH r AS ( " + sqlJoin + " ) "
        "DELETE FROM trustlines WHERE (accountid, issuer, assetcode) in (SELECT * FROM r)";

    auto prep = DB.getPreparedStatement(sql);
    auto sqliteStatement = dynamic_cast<soci::sqlite3_statement_backend*>(prep.statement().get_backend());
    auto st = sqliteStatement->stmt_;
    sqlite3_reset(st);
    sqlite3_bind_pointer(st, 1, cStrAccountIDs.data(), "carray", 0);
    sqlite3_bind_int(st, 2, cStrAccountIDs.size());
    sqlite3_bind_pointer(st, 3, cStrIssuers.data(), "carray", 0);
    sqlite3_bind_int(st, 4, cStrIssuers.size());
    sqlite3_bind_pointer(st, 5, cStrAssetCodes.data(), "carray", 0);
    sqlite3_bind_int(st, 6, cStrAssetCodes.size());

    {
        auto timer = DB.getDeleteTimer("trustline");
        if (sqlite3_step(st) != SQLITE_DONE)
        {
            throw std::runtime_error("SQLite failure");
        }
    }
    soci::session& session = DB.getSession();
    auto sqlite =
        dynamic_cast<soci::sqlite3_session_backend*>(session.get_backend());
    if (sqlite3_changes(sqlite->conn_) != accountIDs.size() &&
        cons == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

#ifdef USE_POSTGRES
static void
postgresSpecificBulkUpsertTrustLines(
    Database& DB, std::vector<std::string> const& accountIDs,
    std::vector<int32_t> const& assetTypes,
    std::vector<std::string> const& issuers,
    std::vector<std::string> const& assetCodes,
    std::vector<int64_t> const& tlimits, std::vector<int64_t> const& balances,
    std::vector<int32_t> const& flags,
    std::vector<int32_t> const& lastModifieds,
    std::vector<int64_t> const& buyingLiabilities,
    std::vector<int64_t> const& sellingLiabilities,
    std::vector<soci::indicator>& liabilitiesInds)
{
    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;

    std::string strAccountIDs, strAssetTypes, strIssuers, strAssetCodes,
        strTlimits, strBalances, strFlags, strLastModifieds,
        strBuyingLiabilities, strSellingLiabilities;

    marshalToPGArray(conn, strAccountIDs, accountIDs);
    marshalToPGArray(conn, strAssetTypes, assetTypes);
    marshalToPGArray(conn, strIssuers, issuers);
    marshalToPGArray(conn, strAssetCodes, assetCodes);
    marshalToPGArray(conn, strTlimits, tlimits);
    marshalToPGArray(conn, strBalances, balances);
    marshalToPGArray(conn, strFlags, flags);
    marshalToPGArray(conn, strLastModifieds, lastModifieds);
    marshalToPGArray(conn, strBuyingLiabilities, buyingLiabilities,
                     &liabilitiesInds);
    marshalToPGArray(conn, strSellingLiabilities, sellingLiabilities,
                     &liabilitiesInds);

    std::string sql =
        "WITH r AS (SELECT "
        "unnest(:ids::TEXT[]), "
        "unnest(:assettypes::INT[]), "
        "unnest(:issuers::TEXT[]), "
        "unnest(:assetcodes::TEXT[]), "
        "unnest(:tlimits::BIGINT[]), "
        "unnest(:balances::BIGINT[]), "
        "unnest(:flags::INT[]), "
        "unnest(:lastmodifieds::INT[]), "
        "unnest(:buyingliabilities::BIGINT[]), "
        "unnest(:sellingliabilities::BIGINT[]) "
        ")"
        "INSERT INTO trustlines ( "
        "accountid, assettype, issuer, assetcode,"
        "tlimit, balance, flags, lastmodified, "
        "buyingliabilities, sellingliabilities "
        ") SELECT * from r "
        "ON CONFLICT (accountid, issuer, assetcode) DO UPDATE SET "
        "assettype = excluded.assettype, "
        "tlimit = excluded.tlimit, "
        "balance = excluded.balance, "
        "flags = excluded.flags, "
        "lastmodified = excluded.lastmodified, "
        "buyingliabilities = excluded.buyingliabilities, "
        "sellingliabilities = excluded.sellingliabilities ";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strAccountIDs, "ids"));
    st.exchange(soci::use(strAssetTypes, "assettypes"));
    st.exchange(soci::use(strIssuers, "issuers"));
    st.exchange(soci::use(strAssetCodes, "assetcodes"));
    st.exchange(soci::use(strTlimits, "tlimits"));
    st.exchange(soci::use(strBalances, "balances"));
    st.exchange(soci::use(strFlags, "flags"));
    st.exchange(soci::use(strLastModifieds, "lastmodifieds"));
    st.exchange(soci::use(strBuyingLiabilities, "buyingliabilities"));
    st.exchange(soci::use(strSellingLiabilities, "sellingliabilities"));
    st.define_and_bind();
    {
        auto timer = DB.getUpsertTimer("trustline");
        st.execute(true);
    }
    if (st.get_affected_rows() != accountIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
postgresSpecificBulkDeleteTrustLines(Database& DB, LedgerTxnConsistency cons,
                                     std::vector<std::string> const& accountIDs,
                                     std::vector<std::string> const& issuers,
                                     std::vector<std::string> const& assetCodes)
{
    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;
    std::string strAccountIDs, strIssuers, strAssetCodes;
    marshalToPGArray(conn, strAccountIDs, accountIDs);
    marshalToPGArray(conn, strIssuers, issuers);
    marshalToPGArray(conn, strAssetCodes, assetCodes);
    std::string sql = "WITH r AS (SELECT "
                      "unnest(:ids::TEXT[]), "
                      "unnest(:issuers::TEXT[]), "
                      "unnest(:assetcodes::TEXT[]) "
                      ") "
                      "DELETE FROM trustlines WHERE "
                      "(accountid, issuer, assetcode) IN (SELECT * FROM r)";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strAccountIDs, "ids"));
    st.exchange(soci::use(strIssuers, "issuers"));
    st.exchange(soci::use(strAssetCodes, "assetcodes"));
    st.define_and_bind();
    {
        auto timer = DB.getDeleteTimer("trustline");
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
LedgerTxnRoot::Impl::bulkUpsertTrustLines(
    std::vector<EntryIterator> const& entries)
{
    std::vector<std::string> accountIDs;
    std::vector<int32_t> assetTypes;
    std::vector<std::string> issuers;
    std::vector<std::string> assetCodes;
    std::vector<int64_t> tlimits;
    std::vector<int64_t> balances;
    std::vector<int32_t> flags;
    std::vector<int32_t> lastModifieds;
    std::vector<int64_t> buyingLiabilities;
    std::vector<int64_t> sellingLiabilities;
    std::vector<soci::indicator> liabilitiesInds;

    accountIDs.reserve(entries.size());
    assetTypes.reserve(entries.size());
    issuers.reserve(entries.size());
    assetCodes.reserve(entries.size());
    tlimits.reserve(entries.size());
    balances.reserve(entries.size());
    flags.reserve(entries.size());
    lastModifieds.reserve(entries.size());
    buyingLiabilities.reserve(entries.size());
    sellingLiabilities.reserve(entries.size());
    liabilitiesInds.reserve(entries.size());

    for (auto const& e : entries)
    {
        assert(e.entryExists());
        assert(e.entry().data.type() == TRUSTLINE);
        auto const& tl = e.entry().data.trustLine();
        std::string accountIDStr, issuerStr, assetCodeStr;
        getTrustLineStrings(tl.accountID, tl.asset, accountIDStr, issuerStr,
                            assetCodeStr);

        accountIDs.push_back(accountIDStr);
        assetTypes.push_back(
            unsignedToSigned(static_cast<uint32_t>(tl.asset.type())));
        issuers.push_back(issuerStr);
        assetCodes.push_back(assetCodeStr);
        tlimits.push_back(tl.limit);
        balances.push_back(tl.balance);
        flags.push_back(unsignedToSigned(tl.flags));
        lastModifieds.push_back(
            unsignedToSigned(e.entry().lastModifiedLedgerSeq));

        if (tl.ext.v() >= 1)
        {
            buyingLiabilities.push_back(tl.ext.v1().liabilities.buying);
            sellingLiabilities.push_back(tl.ext.v1().liabilities.selling);
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
        sqliteSpecificBulkUpsertTrustLines(mDatabase, accountIDs, assetTypes,
                                           issuers, assetCodes, tlimits, balances,
                                           flags, lastModifieds, buyingLiabilities,
                                           sellingLiabilities, liabilitiesInds);
    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkUpsertTrustLines(
            mDatabase, accountIDs, assetTypes, issuers, assetCodes, tlimits,
            balances, flags, lastModifieds, buyingLiabilities,
            sellingLiabilities, liabilitiesInds);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::bulkDeleteTrustLines(
    std::vector<EntryIterator> const& entries)
{
    std::vector<std::string> accountIDs;
    std::vector<std::string> issuers;
    std::vector<std::string> assetCodes;
    for (auto const& e : entries)
    {
        assert(!e.entryExists());
        assert(e.key().type() == TRUSTLINE);
        auto const& tl = e.key().trustLine();
        std::string accountIDStr, issuerStr, assetCodeStr;
        getTrustLineStrings(tl.accountID, tl.asset, accountIDStr, issuerStr,
                            assetCodeStr);
        accountIDs.push_back(accountIDStr);
        issuers.push_back(issuerStr);
        assetCodes.push_back(assetCodeStr);
        dropFromEntryCacheIfPresent(e.key());
    }
    // At the moment we only have two flavors of database support, this
    // condition 2-way split will need to change if we support more.
    if (mDatabase.isSqlite())
    {
        sqliteSpecificBulkDeleteTrustLines(mDatabase, mConsistency, accountIDs,
                                           issuers, assetCodes);
    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkDeleteTrustLines(mDatabase, mConsistency,
                                             accountIDs, issuers, assetCodes);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::dropTrustLines()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffersCache.clear();

    mDatabase.getSession() << "DROP TABLE IF EXISTS trustlines;";
    mDatabase.getSession()
        << "CREATE TABLE trustlines"
           "("
           "accountid    VARCHAR(56)     NOT NULL,"
           "assettype    INT             NOT NULL,"
           "issuer       VARCHAR(56)     NOT NULL,"
           "assetcode    VARCHAR(12)     NOT NULL,"
           "tlimit       BIGINT          NOT NULL CHECK (tlimit > 0),"
           "balance      BIGINT          NOT NULL CHECK (balance >= 0),"
           "flags        INT             NOT NULL,"
           "lastmodified INT             NOT NULL,"
           "PRIMARY KEY  (accountid, issuer, assetcode)"
           ");";
}
}
