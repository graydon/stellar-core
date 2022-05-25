// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
#include "ledger/LedgerTxnImpl.h"
#include "ledger/NonSociRelatedException.h"
#include "util/GlobalChecks.h"
#include "util/types.h"

namespace stellar
{

static void
throwIfNotContractCode(LedgerEntryType type)
{
    if (type != CONTRACT_CODE)
    {
        throw NonSociRelatedException("LedgerEntry is not a CONTRACT_CODE");
    }
}

std::shared_ptr<LedgerEntry const>
LedgerTxnRoot::Impl::loadContractCode(LedgerKey const& key) const
{
    auto contractID = toOpaqueBase64(key.contractCode().contractID);
    std::string contractCodeEntryStr;

    std::string sql = "SELECT ledgerentry "
                      "FROM contractcode "
                      "WHERE contractID = :contractID";
    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    st.exchange(soci::into(contractCodeEntryStr));
    st.exchange(soci::use(contractID));
    st.define_and_bind();
    {
        auto timer = mDatabase.getSelectTimer("contractcode");
        st.execute(true);
    }
    if (!st.got_data())
    {
        return nullptr;
    }

    LedgerEntry le;
    fromOpaqueBase64(le, contractCodeEntryStr);
    throwIfNotContractCode(le.data.type());

    return std::make_shared<LedgerEntry const>(std::move(le));
}

class BulkLoadContractCodeOperation
    : public DatabaseTypeSpecificOperation<std::vector<LedgerEntry>>
{
    Database& mDb;
    std::vector<std::string> mContractIDs;

    std::vector<LedgerEntry>
    executeAndFetch(soci::statement& st)
    {
        std::string contractCodeEntryStr;

        st.exchange(soci::into(contractCodeEntryStr));
        st.define_and_bind();
        {
            auto timer = mDb.getSelectTimer("contractcode");
            st.execute(true);
        }

        std::vector<LedgerEntry> res;
        while (st.got_data())
        {
            res.emplace_back();
            auto& le = res.back();

            fromOpaqueBase64(le, contractCodeEntryStr);
            throwIfNotContractCode(le.data.type());

            st.fetch();
        }
        return res;
    }

  public:
    BulkLoadContractCodeOperation(Database& db,
                                  UnorderedSet<LedgerKey> const& keys)
        : mDb(db)
    {
        mContractIDs.reserve(keys.size());
        for (auto const& k : keys)
        {
            throwIfNotContractCode(k.type());
            mContractIDs.emplace_back(
                toOpaqueBase64(k.contractCode().contractID));
        }
    }

    std::vector<LedgerEntry>
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        std::string sql = "WITH r AS (SELECT value FROM carray(?, ?, 'char*')) "
                          "SELECT ledgerentry "
                          "FROM contractcode "
                          "WHERE contractid IN r";

        auto prep = mDb.getPreparedStatement(sql);
        auto be = prep.statement().get_backend();
        if (be == nullptr)
        {
            throw std::runtime_error("no sql backend");
        }
        auto sqliteStatement =
            dynamic_cast<soci::sqlite3_statement_backend*>(be);
        auto st = sqliteStatement->stmt_;

        sqlite3_reset(st);
        sqlite3_bind_pointer(st, 1, (void*)mContractIDs.data(), "carray", 0);
        sqlite3_bind_int(st, 2, static_cast<int>(mContractIDs.size()));
        return executeAndFetch(prep.statement());
    }

#ifdef USE_POSTGRES
    std::vector<LedgerEntry>
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        std::string strContractIDs;
        marshalToPGArray(pg->conn_, strContractIDs, mContractIDs);

        std::string sql = "WITH r AS (SELECT unnest(:v1::TEXT[])) "
                          "SELECT ledgerentry "
                          "FROM contractcode "
                          "WHERE contractid IN (SELECT * from r)";

        auto prep = mDb.getPreparedStatement(sql);
        auto& st = prep.statement();
        st.exchange(soci::use(strContractIDs));
        return executeAndFetch(st);
    }
#endif
};

UnorderedMap<LedgerKey, std::shared_ptr<LedgerEntry const>>
LedgerTxnRoot::Impl::bulkLoadContractCode(
    UnorderedSet<LedgerKey> const& keys) const
{
    if (!keys.empty())
    {
        BulkLoadContractCodeOperation op(mDatabase, keys);
        return populateLoadedEntries(
            keys, mDatabase.doDatabaseTypeSpecificOperation(op));
    }
    else
    {
        return {};
    }
}

class BulkDeleteContractCodeOperation
    : public DatabaseTypeSpecificOperation<void>
{
    Database& mDb;
    LedgerTxnConsistency mCons;
    std::vector<std::string> mContractIDs;

  public:
    BulkDeleteContractCodeOperation(Database& db, LedgerTxnConsistency cons,
                                    std::vector<EntryIterator> const& entries)
        : mDb(db), mCons(cons)
    {
        mContractIDs.reserve(entries.size());
        for (auto const& e : entries)
        {
            releaseAssert(!e.entryExists());
            throwIfNotContractCode(e.key().ledgerKey().type());
            mContractIDs.emplace_back(
                toOpaqueBase64(e.key().ledgerKey().contractCode().contractID));
        }
    }

    void
    doSociGenericOperation()
    {
        std::string sql = "DELETE FROM contractcode WHERE contractid = :id";
        auto prep = mDb.getPreparedStatement(sql);
        auto& st = prep.statement();
        st.exchange(soci::use(mContractIDs));
        st.define_and_bind();
        {
            auto timer = mDb.getDeleteTimer("contractcode");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) !=
                mContractIDs.size() &&
            mCons == LedgerTxnConsistency::EXACT)
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }

    void
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        doSociGenericOperation();
    }

#ifdef USE_POSTGRES
    void
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        std::string strContractIDs;
        marshalToPGArray(pg->conn_, strContractIDs, mContractIDs);

        std::string sql = "WITH r AS (SELECT unnest(:v1::TEXT[])) "
                          "DELETE FROM contractcode "
                          "WHERE contractid IN (SELECT * FROM r)";

        auto prep = mDb.getPreparedStatement(sql);
        auto& st = prep.statement();
        st.exchange(soci::use(strContractIDs));
        st.define_and_bind();
        {
            auto timer = mDb.getDeleteTimer("contractcode");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) !=
                mContractIDs.size() &&
            mCons == LedgerTxnConsistency::EXACT)
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }
#endif
};

void
LedgerTxnRoot::Impl::bulkDeleteContractCode(
    std::vector<EntryIterator> const& entries, LedgerTxnConsistency cons)
{
    BulkDeleteContractCodeOperation op(mDatabase, cons, entries);
    mDatabase.doDatabaseTypeSpecificOperation(op);
}

class BulkUpsertContractCodeOperation
    : public DatabaseTypeSpecificOperation<void>
{
    Database& mDb;
    std::vector<std::string> mContractIDs;
    std::vector<std::string> mContractCodeEntries;
    std::vector<int32_t> mLastModifieds;

    void
    accumulateEntry(LedgerEntry const& entry)
    {
        throwIfNotContractCode(entry.data.type());

        mContractIDs.emplace_back(
            toOpaqueBase64(entry.data.contractCode().contractID));
        mContractCodeEntries.emplace_back(toOpaqueBase64(entry));
        mLastModifieds.emplace_back(
            unsignedToSigned(entry.lastModifiedLedgerSeq));
    }

  public:
    BulkUpsertContractCodeOperation(Database& Db,
                                    std::vector<EntryIterator> const& entryIter)
        : mDb(Db)
    {
        for (auto const& e : entryIter)
        {
            releaseAssert(e.entryExists());
            accumulateEntry(e.entry().ledgerEntry());
        }
    }

    void
    doSociGenericOperation()
    {
        std::string sql = "INSERT INTO contractCode "
                          "(contractid, ledgerentry, lastmodified) "
                          "VALUES "
                          "( :id, :v1, :v2 ) "
                          "ON CONFLICT (contractid) DO UPDATE SET "
                          "ledgerentry = excluded.ledgerentry, "
                          "lastmodified = excluded.lastmodified";

        auto prep = mDb.getPreparedStatement(sql);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(mContractIDs));
        st.exchange(soci::use(mContractCodeEntries));
        st.exchange(soci::use(mLastModifieds));
        st.define_and_bind();
        {
            auto timer = mDb.getUpsertTimer("contractcode");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mContractIDs.size())
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }

    void
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        doSociGenericOperation();
    }

#ifdef USE_POSTGRES
    void
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        std::string strContractIDs, strContractCodeEntries, strLastModifieds;

        PGconn* conn = pg->conn_;
        marshalToPGArray(conn, strContractIDs, mContractIDs);
        marshalToPGArray(conn, strContractCodeEntries, mContractCodeEntries);
        marshalToPGArray(conn, strLastModifieds, mLastModifieds);

        std::string sql = "WITH r AS "
                          "(SELECT unnest(:ids::TEXT[]), unnest(:v1::TEXT[]), "
                          "unnest(:v2::INT[])) "
                          "INSERT INTO contractcode "
                          "(contractid, ledgerentry, lastmodified) "
                          "SELECT * FROM r "
                          "ON CONFLICT (contractid) DO UPDATE SET "
                          "ledgerentry = excluded.ledgerentry, "
                          "lastmodified = excluded.lastmodified";

        auto prep = mDb.getPreparedStatement(sql);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(strContractIDs));
        st.exchange(soci::use(strContractCodeEntries));
        st.exchange(soci::use(strLastModifieds));
        st.define_and_bind();
        {
            auto timer = mDb.getUpsertTimer("contractcode");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mContractIDs.size())
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }
#endif
};

void
LedgerTxnRoot::Impl::bulkUpsertContractCode(
    std::vector<EntryIterator> const& entries)
{
    BulkUpsertContractCodeOperation op(mDatabase, entries);
    mDatabase.doDatabaseTypeSpecificOperation(op);
}

void
LedgerTxnRoot::Impl::dropContractCode()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffers.clear();

    std::string coll = mDatabase.getSimpleCollationClause();

    mDatabase.getSession() << "DROP TABLE IF EXISTS contractcode;";
    mDatabase.getSession() << "CREATE TABLE contractcode ("
                           << "contractid   TEXT " << coll << " PRIMARY KEY, "
                           << "ledgerentry  TEXT " << coll << " NOT NULL, "
                           << "lastmodified INT NOT NULL);";
    if (!mDatabase.isSqlite())
    {
        mDatabase.getSession() << "ALTER TABLE contractcode "
                               << "ALTER COLUMN contractid "
                               << "TYPE TEXT COLLATE \"C\";";
    }
}
}
#endif