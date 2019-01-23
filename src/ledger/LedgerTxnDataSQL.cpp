// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "database/Database.h"
#include "ledger/LedgerTxnImpl.h"
#include "util/Decoder.h"
#include "util/types.h"
#include <soci-sqlite3.h>

namespace stellar
{

std::shared_ptr<LedgerEntry const>
LedgerTxnRoot::Impl::loadData(LedgerKey const& key) const
{
    std::string actIDStrKey = KeyUtils::toStrKey(key.data().accountID);
    std::string const& dataName = key.data().dataName;

    std::string dataValue;
    soci::indicator dataValueIndicator;

    LedgerEntry le;
    le.data.type(DATA);
    DataEntry& de = le.data.data();

    std::string sql = "SELECT datavalue, lastmodified "
                      "FROM accountdata "
                      "WHERE accountid= :id AND dataname= :dataname";
    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    st.exchange(soci::into(dataValue, dataValueIndicator));
    st.exchange(soci::into(le.lastModifiedLedgerSeq));
    st.exchange(soci::use(actIDStrKey));
    st.exchange(soci::use(dataName));
    st.define_and_bind();
    st.execute(true);
    if (!st.got_data())
    {
        return nullptr;
    }

    de.accountID = key.data().accountID;
    de.dataName = dataName;

    if (dataValueIndicator != soci::i_ok)
    {
        throw std::runtime_error("bad database state");
    }
    decoder::decode_b64(dataValue, de.dataValue);

    return std::make_shared<LedgerEntry const>(std::move(le));
}

void
LedgerTxnRoot::Impl::insertOrUpdateData(LedgerEntry const& entry, bool isInsert)
{
    auto const& data = entry.data.data();
    std::string actIDStrKey = KeyUtils::toStrKey(data.accountID);
    std::string const& dataName = data.dataName;
    std::string dataValue = decoder::encode_b64(data.dataValue);

    std::string sql;
    if (isInsert)
    {
        sql = "INSERT INTO accountdata "
              "(accountid,dataname,datavalue,lastmodified)"
              " VALUES (:aid,:dn,:dv,:lm)";
    }
    else
    {
        sql = "UPDATE accountdata SET datavalue=:dv,lastmodified=:lm "
              " WHERE accountid=:aid AND dataname=:dn";
    }

    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    uint32_t signedLastModified = unsignedToSigned(entry.lastModifiedLedgerSeq);
    st.exchange(soci::use(actIDStrKey, "aid"));
    st.exchange(soci::use(dataName, "dn"));
    st.exchange(soci::use(dataValue, "dv"));
    st.exchange(soci::use(signedLastModified, "lm"));
    st.define_and_bind();
    st.execute(true);
    if (st.get_affected_rows() != 1)
    {
        throw std::runtime_error("could not update SQL");
    }
}

void
LedgerTxnRoot::Impl::deleteData(LedgerKey const& key)
{
    auto const& data = key.data();
    std::string actIDStrKey = KeyUtils::toStrKey(data.accountID);
    std::string const& dataName = data.dataName;

    auto prep = mDatabase.getPreparedStatement(
        "DELETE FROM accountdata WHERE accountid=:id AND dataname=:s");
    auto& st = prep.statement();
    st.exchange(soci::use(actIDStrKey));
    st.exchange(soci::use(dataName));
    st.define_and_bind();
    {
        auto timer = mDatabase.getDeleteTimer("data");
        st.execute(true);
    }
    if (st.get_affected_rows() != 1 &&
        mConsistency == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sqliteSpecificBulkUpsertAccountData(Database& DB,
                                    std::vector<std::string> const& accountIDs,
                                    std::vector<std::string> const& dataNames,
                                    std::vector<std::string> const& dataValues,
                                    std::vector<int32_t> lastModifieds)
{
    std::vector<const char*> cStrAccountIDs, cStrDataNames, cStrDataValues;
    marshalToSqliteArray(cStrAccountIDs, accountIDs);
    marshalToSqliteArray(cStrDataNames, dataNames);
    marshalToSqliteArray(cStrDataValues, dataValues);

    std::string sqlJoin =
        "SELECT v1.value, v2.value, v3.value, v4.value "
        " FROM "
        "           (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v1 "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v2 ON v1.rowid = v2.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v3 ON v1.rowid = v3.rowid "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32') ORDER BY rowid) AS v4 ON v1.rowid = v4.rowid ";

    std::string sql =
        "WITH r AS ( " + sqlJoin + " ) "
        "INSERT INTO accountdata ( "
        "accountid, dataname, datavalue, lastmodified "
        ") SELECT * FROM r "

        // NB: this 'WHERE true' is the official way to resolve a
        // parsing ambiguity wrt. the following 'ON' token. Really.
        // See: https://www.sqlite.org/lang_insert.html
        "WHERE true "

        "ON CONFLICT (accountid, dataname) DO UPDATE SET "
        "datavalue = excluded.datavalue, "
        "lastmodified = excluded.lastmodified ";

    auto prep = DB.getPreparedStatement(sql);
    auto sqliteStatement = dynamic_cast<soci::sqlite3_statement_backend*>(prep.statement().get_backend());
    auto st = sqliteStatement->stmt_;
    sqlite3_reset(st);
    sqlite3_bind_pointer(st, 1, cStrAccountIDs.data(), "carray", 0);
    sqlite3_bind_int(st, 2, cStrAccountIDs.size());
    sqlite3_bind_pointer(st, 3, cStrDataNames.data(), "carray", 0);
    sqlite3_bind_int(st, 4, cStrDataNames.size());
    sqlite3_bind_pointer(st, 5, cStrDataValues.data(), "carray", 0);
    sqlite3_bind_int(st, 6, cStrDataValues.size());
    sqlite3_bind_pointer(st, 7, const_cast<int32_t*>(lastModifieds.data()), "carray", 0);
    sqlite3_bind_int(st, 8, lastModifieds.size());

    {
        auto timer = DB.getUpsertTimer("data");
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
sqliteSpecificBulkDeleteAccountData(Database& DB, LedgerTxnConsistency cons,
                                    std::vector<std::string> const& accountIDs,
                                    std::vector<std::string> const& dataNames)
{
    std::vector<const char*> cStrAccountIDs, cStrDataNames;
    marshalToSqliteArray(cStrAccountIDs, accountIDs);
    marshalToSqliteArray(cStrDataNames, dataNames);

    std::string sqlJoin =
        "SELECT v1.value, v2.value "
        " FROM "
        "           (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v1 "
        "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*') ORDER BY rowid) AS v2 ON v1.rowid = v2.rowid ";

    std::string sql = "WITH r AS ( " + sqlJoin + " ) "
        "DELETE FROM accountdata WHERE (accountid, dataname) in (SELECT * FROM r)";

    auto prep = DB.getPreparedStatement(sql);
    auto sqliteStatement = dynamic_cast<soci::sqlite3_statement_backend*>(prep.statement().get_backend());
    auto st = sqliteStatement->stmt_;
    sqlite3_reset(st);
    sqlite3_bind_pointer(st, 1, cStrAccountIDs.data(), "carray", 0);
    sqlite3_bind_int(st, 2, cStrAccountIDs.size());
    sqlite3_bind_pointer(st, 3, cStrDataNames.data(), "carray", 0);
    sqlite3_bind_int(st, 4, cStrDataNames.size());

    {
        auto timer = DB.getDeleteTimer("data");
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
postgresSpecificBulkUpsertAccountData(
    Database& DB, std::vector<std::string> const& accountIDs,
    std::vector<std::string> const& dataNames,
    std::vector<std::string> const& dataValues,
    std::vector<int32_t> lastModifieds)
{

    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;

    std::string strAccountIDs, strDataNames, strDataValues, strLastModifieds;

    marshalToPGArray(conn, strAccountIDs, accountIDs);
    marshalToPGArray(conn, strDataNames, dataNames);
    marshalToPGArray(conn, strDataValues, dataValues);
    marshalToPGArray(conn, strLastModifieds, lastModifieds);

    std::string sql = "WITH r AS (SELECT "
                      "unnest(:ids::TEXT[]), "
                      "unnest(:datanames::TEXT[]), "
                      "unnest(:datavalues::TEXT[]), "
                      "unnest(:lastmodifieds::INT[]) "
                      ")"
                      "INSERT INTO accountdata ( "
                      "accountid, dataname, datavalue, lastmodified "
                      ") SELECT * FROM r "
                      "ON CONFLICT (accountid, dataname) DO UPDATE SET "
                      "datavalue = excluded.datavalue, "
                      "lastmodified = excluded.lastmodified ";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strAccountIDs, "ids"));
    st.exchange(soci::use(strDataNames, "datanames"));
    st.exchange(soci::use(strDataValues, "datavalues"));
    st.exchange(soci::use(strLastModifieds, "lastmodifieds"));
    st.define_and_bind();
    {
        auto timer = DB.getUpsertTimer("data");
        st.execute(true);
    }
    if (st.get_affected_rows() != accountIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
postgresSpecificBulkDeleteAccountData(
    Database& DB, LedgerTxnConsistency cons,
    std::vector<std::string> const& accountIDs,
    std::vector<std::string> const& dataNames)
{
    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;
    std::string strAccountIDs;
    std::string strDataNames;
    marshalToPGArray(conn, strAccountIDs, accountIDs);
    marshalToPGArray(conn, strDataNames, dataNames);
    std::string sql = "WITH r AS ( SELECT "
                      "unnest(:ids::TEXT[]),"
                      "unnest(:datanames::TEXT[])"
                      " ) "
                      "DELETE FROM accountdata WHERE (accountid, dataname) IN "
                      "(SELECT * FROM r)";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strAccountIDs, "ids"));
    st.exchange(soci::use(strDataNames, "datanames"));
    st.define_and_bind();
    {
        auto timer = DB.getDeleteTimer("data");
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
LedgerTxnRoot::Impl::bulkUpsertAccountData(
    std::vector<EntryIterator> const& entries)
{
    std::vector<std::string> accountIDs;
    std::vector<std::string> dataNames;
    std::vector<std::string> dataValues;
    std::vector<int32_t> lastModifieds;

    accountIDs.reserve(entries.size());
    dataNames.reserve(entries.size());
    dataValues.reserve(entries.size());
    lastModifieds.reserve(entries.size());

    for (auto const& e : entries)
    {
        assert(e.entryExists());
        assert(e.entry().data.type() == DATA);
        auto const& data = e.entry().data.data();
        accountIDs.push_back(KeyUtils::toStrKey(data.accountID));
        dataNames.push_back(data.dataName);
        dataValues.push_back(decoder::encode_b64(data.dataValue));
        lastModifieds.push_back(
            unsignedToSigned(e.entry().lastModifiedLedgerSeq));

        dropFromEntryCacheIfPresent(e.key());
    }

    // At the moment we only have two flavors of database support, this
    // condition 2-way split will need to change if we support more.
    if (mDatabase.isSqlite())
    {
        sqliteSpecificBulkUpsertAccountData(mDatabase, accountIDs, dataNames,
                                            dataValues, lastModifieds);
    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkUpsertAccountData(mDatabase, accountIDs, dataNames,
                                              dataValues, lastModifieds);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::bulkDeleteAccountData(
    std::vector<EntryIterator> const& entries)
{
    std::vector<std::string> accountIDs;
    std::vector<std::string> dataNames;
    for (auto const& e : entries)
    {
        assert(!e.entryExists());
        assert(e.key().type() == DATA);
        auto const& data = e.key().data();
        accountIDs.push_back(KeyUtils::toStrKey(data.accountID));
        dataNames.push_back(data.dataName);
        dropFromEntryCacheIfPresent(e.key());
    }
    // At the moment we only have two flavors of database support, this
    // condition 2-way split will need to change if we support more.
    if (mDatabase.isSqlite())
    {
        sqliteSpecificBulkDeleteAccountData(mDatabase, mConsistency, accountIDs,
                                            dataNames);
    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkDeleteAccountData(mDatabase, mConsistency,
                                              accountIDs, dataNames);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::dropData()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffersCache.clear();

    mDatabase.getSession() << "DROP TABLE IF EXISTS accountdata;";
    mDatabase.getSession() << "CREATE TABLE accountdata"
                              "("
                              "accountid    VARCHAR(56)  NOT NULL,"
                              "dataname     VARCHAR(64)  NOT NULL,"
                              "datavalue    VARCHAR(112) NOT NULL,"
                              "lastmodified INT          NOT NULL,"
                              "PRIMARY KEY  (accountid, dataname)"
                              ");";
}
}
