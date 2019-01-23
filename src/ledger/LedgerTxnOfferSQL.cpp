// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "database/Database.h"
#include "ledger/LedgerTxnImpl.h"
#include "util/XDROperators.h"
#include "util/Logging.h"
#include "util/types.h"
#include <soci-sqlite3.h>

namespace stellar
{

void
getAssetStrings(Asset const& asset, std::string& assetCodeStr,
                std::string& issuerStr, soci::indicator& assetCodeIndicator,
                soci::indicator& issuerIndicator)
{
    if (asset.type() == ASSET_TYPE_CREDIT_ALPHANUM4)
    {
        assetCodeToStr(asset.alphaNum4().assetCode, assetCodeStr);
        issuerStr = KeyUtils::toStrKey(asset.alphaNum4().issuer);
        assetCodeIndicator = soci::i_ok;
        issuerIndicator = soci::i_ok;
    }
    else if (asset.type() == ASSET_TYPE_CREDIT_ALPHANUM12)
    {
        assetCodeToStr(asset.alphaNum12().assetCode, assetCodeStr);
        issuerStr = KeyUtils::toStrKey(asset.alphaNum12().issuer);
        assetCodeIndicator = soci::i_ok;
        issuerIndicator = soci::i_ok;
    }
    else
    {
        assert(asset.type() == ASSET_TYPE_NATIVE);
        assetCodeStr = "";
        issuerStr = "";
        assetCodeIndicator = soci::i_null;
        issuerIndicator = soci::i_null;
    }
}

void
processAsset(Asset& asset, AssetType assetType, std::string const& issuerStr,
             soci::indicator const& issuerIndicator,
             std::string const& assetCode,
             soci::indicator const& assetCodeIndicator)
{
    asset.type(assetType);
    if (assetType != ASSET_TYPE_NATIVE)
    {
        if ((assetCodeIndicator != soci::i_ok) ||
            (issuerIndicator != soci::i_ok))
        {
            throw std::runtime_error("bad database state");
        }

        if (assetType == ASSET_TYPE_CREDIT_ALPHANUM12)
        {
            asset.alphaNum12().issuer =
                KeyUtils::fromStrKey<PublicKey>(issuerStr);
            strToAssetCode(asset.alphaNum12().assetCode, assetCode);
        }
        else if (assetType == ASSET_TYPE_CREDIT_ALPHANUM4)
        {
            asset.alphaNum4().issuer =
                KeyUtils::fromStrKey<PublicKey>(issuerStr);
            strToAssetCode(asset.alphaNum4().assetCode, assetCode);
        }
        else
        {
            throw std::runtime_error("bad database state");
        }
    }
}

std::shared_ptr<LedgerEntry const>
LedgerTxnRoot::Impl::loadOffer(LedgerKey const& key) const
{
    uint64_t offerID = key.offer().offerID;
    std::string actIDStrKey = KeyUtils::toStrKey(key.offer().sellerID);

    std::string sql = "SELECT sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, flags, lastmodified "
                      "FROM offers "
                      "WHERE sellerid= :id AND offerid= :offerid";
    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    st.exchange(soci::use(actIDStrKey));
    int64_t signedOfferID = unsignedToSigned(offerID);
    st.exchange(soci::use(signedOfferID));

    std::vector<LedgerEntry> offers;
    {
        auto timer = mDatabase.getSelectTimer("offer");
        offers = loadOffers(prep);
    }

    return offers.size() == 0
               ? nullptr
               : std::make_shared<LedgerEntry const>(offers.front());
}

std::vector<LedgerEntry>
LedgerTxnRoot::Impl::loadAllOffers() const
{
    std::string sql = "SELECT sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, flags, lastmodified "
                      "FROM offers";
    auto prep = mDatabase.getPreparedStatement(sql);

    std::vector<LedgerEntry> offers;
    {
        auto timer = mDatabase.getSelectTimer("offer");
        offers = loadOffers(prep);
    }
    return offers;
}

std::list<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadBestOffers(std::list<LedgerEntry>& offers,
                                    Asset const& buying, Asset const& selling,
                                    size_t numOffers, size_t offset) const
{
    std::string sql = "SELECT sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, flags, lastmodified "
                      "FROM offers ";

    std::string sellingAssetCode, sellingIssuerStrKey;
    if (selling.type() == ASSET_TYPE_NATIVE)
    {
        sql += " WHERE sellingassettype = 0 AND sellingissuer IS NULL";
    }
    else
    {
        if (selling.type() == ASSET_TYPE_CREDIT_ALPHANUM4)
        {
            assetCodeToStr(selling.alphaNum4().assetCode, sellingAssetCode);
            sellingIssuerStrKey =
                KeyUtils::toStrKey(selling.alphaNum4().issuer);
        }
        else if (selling.type() == ASSET_TYPE_CREDIT_ALPHANUM12)
        {
            assetCodeToStr(selling.alphaNum12().assetCode, sellingAssetCode);
            sellingIssuerStrKey =
                KeyUtils::toStrKey(selling.alphaNum12().issuer);
        }
        else
        {
            throw std::runtime_error("unknown asset type");
        }
        sql += " WHERE sellingassetcode = :sac AND sellingissuer = :si";
    }

    std::string buyingAssetCode, buyingIssuerStrKey;
    if (buying.type() == ASSET_TYPE_NATIVE)
    {
        sql += " AND buyingassettype = 0 AND buyingissuer IS NULL";
    }
    else
    {
        if (buying.type() == ASSET_TYPE_CREDIT_ALPHANUM4)
        {
            assetCodeToStr(buying.alphaNum4().assetCode, buyingAssetCode);
            buyingIssuerStrKey = KeyUtils::toStrKey(buying.alphaNum4().issuer);
        }
        else if (buying.type() == ASSET_TYPE_CREDIT_ALPHANUM12)
        {
            assetCodeToStr(buying.alphaNum12().assetCode, buyingAssetCode);
            buyingIssuerStrKey = KeyUtils::toStrKey(buying.alphaNum12().issuer);
        }
        else
        {
            throw std::runtime_error("unknown asset type");
        }
        sql += " AND buyingassetcode = :bac AND buyingissuer = :bi";
    }

    // price is an approximation of the actual n/d (truncated math, 15 digits)
    // ordering by offerid gives precendence to older offers for fairness
    sql += " ORDER BY price, offerid LIMIT :n OFFSET :o";

    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    if (selling.type() != ASSET_TYPE_NATIVE)
    {
        st.exchange(soci::use(sellingAssetCode, "sac"));
        st.exchange(soci::use(sellingIssuerStrKey, "si"));
    }
    if (buying.type() != ASSET_TYPE_NATIVE)
    {
        st.exchange(soci::use(buyingAssetCode, "bac"));
        st.exchange(soci::use(buyingIssuerStrKey, "bi"));
    }
    st.exchange(soci::use(numOffers, "n"));
    st.exchange(soci::use(offset, "o"));

    {
        auto timer = mDatabase.getSelectTimer("offer");
        return loadOffers(prep, offers);
    }
}

// Note: The order induced by this function must match the order used in the
// SQL query for loadBestOffers above.
bool
isBetterOffer(LedgerEntry const& lhsEntry, LedgerEntry const& rhsEntry)
{
    auto const& lhs = lhsEntry.data.offer();
    auto const& rhs = rhsEntry.data.offer();

    assert(lhs.buying == rhs.buying);
    assert(lhs.selling == rhs.selling);

    double lhsPrice = double(lhs.price.n) / double(lhs.price.d);
    double rhsPrice = double(rhs.price.n) / double(rhs.price.d);
    if (lhsPrice < rhsPrice)
    {
        return true;
    }
    else if (lhsPrice == rhsPrice)
    {
        return lhs.offerID < rhs.offerID;
    }
    else
    {
        return false;
    }
}

// Note: This function is currently only used in AllowTrustOpFrame, which means
// the asset parameter will never satisfy asset.type() == ASSET_TYPE_NATIVE. As
// a consequence, I have not implemented that possibility so this function
// throws in that case.
std::vector<LedgerEntry>
LedgerTxnRoot::Impl::loadOffersByAccountAndAsset(AccountID const& accountID,
                                                 Asset const& asset) const
{
    std::string sql = "SELECT sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, flags, lastmodified "
                      "FROM offers ";
    sql += " WHERE sellerid = :acc"
           " AND ((sellingassetcode = :code AND sellingissuer = :iss)"
           " OR   (buyingassetcode = :code AND buyingissuer = :iss))";

    std::string accountStr = KeyUtils::toStrKey(accountID);

    std::string assetCode;
    std::string assetIssuer;
    if (asset.type() == ASSET_TYPE_CREDIT_ALPHANUM4)
    {
        assetCodeToStr(asset.alphaNum4().assetCode, assetCode);
        assetIssuer = KeyUtils::toStrKey(asset.alphaNum4().issuer);
    }
    else if (asset.type() == ASSET_TYPE_CREDIT_ALPHANUM12)
    {
        assetCodeToStr(asset.alphaNum12().assetCode, assetCode);
        assetIssuer = KeyUtils::toStrKey(asset.alphaNum12().issuer);
    }
    else
    {
        throw std::runtime_error("Invalid asset type");
    }

    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    st.exchange(soci::use(accountStr, "acc"));
    st.exchange(soci::use(assetCode, "code"));
    st.exchange(soci::use(assetIssuer, "iss"));

    std::vector<LedgerEntry> offers;
    {
        auto timer = mDatabase.getSelectTimer("offer");
        offers = loadOffers(prep);
    }
    return offers;
}

std::vector<LedgerEntry>
LedgerTxnRoot::Impl::loadOffers(StatementContext& prep) const
{
    std::vector<LedgerEntry> offers;

    std::string actIDStrKey;
    unsigned int sellingAssetType, buyingAssetType;
    std::string sellingAssetCode, buyingAssetCode, sellingIssuerStrKey,
        buyingIssuerStrKey;
    soci::indicator sellingAssetCodeIndicator, buyingAssetCodeIndicator,
        sellingIssuerIndicator, buyingIssuerIndicator;

    LedgerEntry le;
    le.data.type(OFFER);
    OfferEntry& oe = le.data.offer();

    auto& st = prep.statement();
    st.exchange(soci::into(actIDStrKey));
    st.exchange(soci::into(oe.offerID));
    st.exchange(soci::into(sellingAssetType));
    st.exchange(soci::into(sellingAssetCode, sellingAssetCodeIndicator));
    st.exchange(soci::into(sellingIssuerStrKey, sellingIssuerIndicator));
    st.exchange(soci::into(buyingAssetType));
    st.exchange(soci::into(buyingAssetCode, buyingAssetCodeIndicator));
    st.exchange(soci::into(buyingIssuerStrKey, buyingIssuerIndicator));
    st.exchange(soci::into(oe.amount));
    st.exchange(soci::into(oe.price.n));
    st.exchange(soci::into(oe.price.d));
    st.exchange(soci::into(oe.flags));
    st.exchange(soci::into(le.lastModifiedLedgerSeq));
    st.define_and_bind();
    st.execute(true);
    while (st.got_data())
    {
        oe.sellerID = KeyUtils::fromStrKey<PublicKey>(actIDStrKey);
        processAsset(oe.selling, (AssetType)sellingAssetType,
                     sellingIssuerStrKey, sellingIssuerIndicator,
                     sellingAssetCode, sellingAssetCodeIndicator);
        processAsset(oe.buying, (AssetType)buyingAssetType, buyingIssuerStrKey,
                     buyingIssuerIndicator, buyingAssetCode,
                     buyingAssetCodeIndicator);

        offers.emplace_back(le);
        st.fetch();
    }

    return offers;
}

std::list<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadOffers(StatementContext& prep,
                                std::list<LedgerEntry>& offers) const
{
    std::string actIDStrKey;
    unsigned int sellingAssetType, buyingAssetType;
    std::string sellingAssetCode, buyingAssetCode, sellingIssuerStrKey,
        buyingIssuerStrKey;
    soci::indicator sellingAssetCodeIndicator, buyingAssetCodeIndicator,
        sellingIssuerIndicator, buyingIssuerIndicator;

    LedgerEntry le;
    le.data.type(OFFER);
    OfferEntry& oe = le.data.offer();

    auto& st = prep.statement();
    st.exchange(soci::into(actIDStrKey));
    st.exchange(soci::into(oe.offerID));
    st.exchange(soci::into(sellingAssetType));
    st.exchange(soci::into(sellingAssetCode, sellingAssetCodeIndicator));
    st.exchange(soci::into(sellingIssuerStrKey, sellingIssuerIndicator));
    st.exchange(soci::into(buyingAssetType));
    st.exchange(soci::into(buyingAssetCode, buyingAssetCodeIndicator));
    st.exchange(soci::into(buyingIssuerStrKey, buyingIssuerIndicator));
    st.exchange(soci::into(oe.amount));
    st.exchange(soci::into(oe.price.n));
    st.exchange(soci::into(oe.price.d));
    st.exchange(soci::into(oe.flags));
    st.exchange(soci::into(le.lastModifiedLedgerSeq));
    st.define_and_bind();
    st.execute(true);

    auto iterNext = offers.cend();
    while (st.got_data())
    {
        oe.sellerID = KeyUtils::fromStrKey<PublicKey>(actIDStrKey);
        processAsset(oe.selling, (AssetType)sellingAssetType,
                     sellingIssuerStrKey, sellingIssuerIndicator,
                     sellingAssetCode, sellingAssetCodeIndicator);
        processAsset(oe.buying, (AssetType)buyingAssetType, buyingIssuerStrKey,
                     buyingIssuerIndicator, buyingAssetCode,
                     buyingAssetCodeIndicator);

        if (iterNext == offers.cend())
        {
            iterNext = offers.emplace(iterNext, le);
        }
        else
        {
            offers.emplace_back(le);
        }
        st.fetch();
    }

    return iterNext;
}

void
LedgerTxnRoot::Impl::insertOrUpdateOffer(LedgerEntry const& entry,
                                         bool isInsert)
{
    auto const& offer = entry.data.offer();
    std::string actIDStrKey = KeyUtils::toStrKey(offer.sellerID);

    unsigned int sellingType = offer.selling.type();
    unsigned int buyingType = offer.buying.type();
    std::string sellingIssuerStrKey, buyingIssuerStrKey;
    std::string sellingAssetCode, buyingAssetCode;
    soci::indicator selling_ind = soci::i_null, buying_ind = soci::i_null;
    double price = double(offer.price.n) / double(offer.price.d);

    if (sellingType == ASSET_TYPE_CREDIT_ALPHANUM4)
    {
        sellingIssuerStrKey =
            KeyUtils::toStrKey(offer.selling.alphaNum4().issuer);
        assetCodeToStr(offer.selling.alphaNum4().assetCode, sellingAssetCode);
        selling_ind = soci::i_ok;
    }
    else if (sellingType == ASSET_TYPE_CREDIT_ALPHANUM12)
    {
        sellingIssuerStrKey =
            KeyUtils::toStrKey(offer.selling.alphaNum12().issuer);
        assetCodeToStr(offer.selling.alphaNum12().assetCode, sellingAssetCode);
        selling_ind = soci::i_ok;
    }

    if (buyingType == ASSET_TYPE_CREDIT_ALPHANUM4)
    {
        buyingIssuerStrKey =
            KeyUtils::toStrKey(offer.buying.alphaNum4().issuer);
        assetCodeToStr(offer.buying.alphaNum4().assetCode, buyingAssetCode);
        buying_ind = soci::i_ok;
    }
    else if (buyingType == ASSET_TYPE_CREDIT_ALPHANUM12)
    {
        buyingIssuerStrKey =
            KeyUtils::toStrKey(offer.buying.alphaNum12().issuer);
        assetCodeToStr(offer.buying.alphaNum12().assetCode, buyingAssetCode);
        buying_ind = soci::i_ok;
    }

    std::string sql;
    if (isInsert)
    {
        sql = "INSERT INTO offers (sellerid,offerid,"
              "sellingassettype,sellingassetcode,sellingissuer,"
              "buyingassettype,buyingassetcode,buyingissuer,"
              "amount,pricen,priced,price,flags,lastmodified) VALUES "
              "(:sid,:oid,:sat,:sac,:si,:bat,:bac,:bi,:a,:pn,:pd,:p,:f,:l)";
    }
    else
    {
        sql = "UPDATE offers SET sellingassettype=:sat,"
              "sellingassetcode=:sac,sellingissuer=:si,"
              "buyingassettype=:bat,buyingassetcode=:bac,buyingissuer=:bi,"
              "amount=:a,pricen=:pn,priced=:pd,price=:p,flags=:f,"
              "lastmodified=:l WHERE offerid=:oid";
    }

    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    if (isInsert)
    {
        st.exchange(soci::use(actIDStrKey, "sid"));
    }
    int64_t signedOfferID = unsignedToSigned(offer.offerID);
    int32_t signedLastModified = unsignedToSigned(entry.lastModifiedLedgerSeq);
    int32_t signedFlags = unsignedToSigned(offer.flags);
    st.exchange(soci::use(signedOfferID, "oid"));
    st.exchange(soci::use(sellingType, "sat"));
    st.exchange(soci::use(sellingAssetCode, selling_ind, "sac"));
    st.exchange(soci::use(sellingIssuerStrKey, selling_ind, "si"));
    st.exchange(soci::use(buyingType, "bat"));
    st.exchange(soci::use(buyingAssetCode, buying_ind, "bac"));
    st.exchange(soci::use(buyingIssuerStrKey, buying_ind, "bi"));
    st.exchange(soci::use(offer.amount, "a"));
    st.exchange(soci::use(offer.price.n, "pn"));
    st.exchange(soci::use(offer.price.d, "pd"));
    st.exchange(soci::use(price, "p"));
    st.exchange(soci::use(signedFlags, "f"));
    st.exchange(soci::use(signedLastModified, "l"));
    st.define_and_bind();
    {
        auto timer = isInsert ? mDatabase.getInsertTimer("offer")
                              : mDatabase.getUpdateTimer("offer");
        st.execute(true);
    }
    if (st.get_affected_rows() != 1)
    {
        throw std::runtime_error("could not update SQL");
    }
}

void
LedgerTxnRoot::Impl::deleteOffer(LedgerKey const& key)
{
    auto const& offer = key.offer();

    auto prep =
        mDatabase.getPreparedStatement("DELETE FROM offers WHERE offerid=:s");
    auto& st = prep.statement();
    int64_t signedOfferID = unsignedToSigned(offer.offerID);
    st.exchange(soci::use(signedOfferID));
    st.define_and_bind();
    {
        auto timer = mDatabase.getDeleteTimer("offer");
        st.execute(true);
    }
    if (st.get_affected_rows() != 1 &&
        mConsistency == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sqliteSpecificBulkUpsertOffersUsingJson(
    Database& DB, std::vector<EntryIterator> const& entries)
{
    std::vector<std::string> jsonArrays;
    std::vector<const char*> jsonArrayPtrs;

    for (auto const& e : entries)
    {
        std::ostringstream oss;
        assert(e.entryExists());
        assert(e.entry().data.type() == OFFER);
        auto const& offer = e.entry().data.offer();
        std::string sellerIDStr, sellingIssuerStr, sellingAssetCodeStr,
            buyingIssuerStr, buyingAssetCodeStr;
        soci::indicator sellingIssuerInd, sellingAssetCodeInd, buyingIssuerInd,
            buyingAssetCodeInd;
        getAssetStrings(offer.selling, sellingAssetCodeStr, sellingIssuerStr,
                        sellingAssetCodeInd, sellingIssuerInd);
        getAssetStrings(offer.buying, buyingAssetCodeStr, buyingIssuerStr,
                        buyingAssetCodeInd, buyingIssuerInd);

        oss << '[' << '"' << KeyUtils::toStrKey(offer.sellerID) << '"'
            << ',' << offer.offerID
            << ',' << unsignedToSigned(static_cast<uint32_t>(offer.selling.type()));
        if (sellingAssetCodeInd == soci::i_ok) {
            oss << ',' << '"' << sellingAssetCodeStr << '"'
                << ',' << '"' << sellingIssuerStr << '"';
        } else {
            oss << ",null,null";
        }
        oss << ',' << unsignedToSigned(static_cast<uint32_t>(offer.buying.type()));
        if (buyingAssetCodeInd == soci::i_ok) {
            oss << ',' << '"' << buyingAssetCodeStr << '"'
                << ',' << '"' << buyingIssuerStr << '"';
        } else {
            oss << ",null,null";
        }
        oss << ',' << offer.amount
            << ',' << offer.price.n
            << ',' << offer.price.d;
        double price = double(offer.price.n) / double(offer.price.d);
        oss << ',' << price
            << ',' << unsignedToSigned(offer.flags)
            << ',' << unsignedToSigned(e.entry().lastModifiedLedgerSeq)
            << ']';
        jsonArrays.push_back(oss.str());
    }
    marshalToSqliteArray(jsonArrayPtrs, jsonArrays);

    std::string sqlJson =
        "SELECT "
        "json_extract(value, '$[0]'), json_extract(value, '$[1]'),"
        "json_extract(value, '$[2]'), json_extract(value, '$[3]'),"
        "json_extract(value, '$[4]'), json_extract(value, '$[5]'),"
        "json_extract(value, '$[6]'), json_extract(value, '$[7]'),"
        "json_extract(value, '$[8]'), json_extract(value, '$[9]'),"
        "json_extract(value, '$[10]'), json_extract(value, '$[11]'),"
        "json_extract(value, '$[12]'), json_extract(value, '$[13]')"
        " FROM carray(?, ?, 'char*')";

    std::string sql = "WITH j AS ( " + sqlJson + ")"
                      "INSERT INTO offers ( "
                      "sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, price, flags, lastmodified "
                      ") SELECT * from j "

                      // NB: this 'WHERE true' is the official way to resolve a
                      // parsing ambiguity wrt. the following 'ON' token. Really.
                      // See: https://www.sqlite.org/lang_insert.html
                      "WHERE true "

                      "ON CONFLICT (offerid) DO UPDATE SET "
                      "sellerid = excluded.sellerid, "
                      "sellingassettype = excluded.sellingassettype, "
                      "sellingassetcode = excluded.sellingassetcode, "
                      "sellingissuer = excluded.sellingissuer, "
                      "buyingassettype = excluded.buyingassettype, "
                      "buyingassetcode = excluded.buyingassetcode, "
                      "buyingissuer = excluded.buyingissuer, "
                      "amount = excluded.amount, "
                      "pricen = excluded.pricen, "
                      "priced = excluded.priced, "
                      "price = excluded.price, "
                      "flags = excluded.flags, "
                      "lastmodified = excluded.lastmodified ";

    auto prep = DB.getPreparedStatement(sql);
    auto sqliteStatement = dynamic_cast<soci::sqlite3_statement_backend*>(prep.statement().get_backend());
    auto st = sqliteStatement->stmt_;

    sqlite3_reset(st);
    sqlite3_bind_pointer(st, 1, jsonArrayPtrs.data(), "carray", 0);
    sqlite3_bind_int(st, 2, jsonArrayPtrs.size());

    {
        auto timer = DB.getUpsertTimer("offer");
        CLOG(INFO, "Ledger") << "Bulk-upsert'ing " << jsonArrayPtrs.size()
                             << " offers";
        if (sqlite3_step(st) != SQLITE_DONE)
        {
            throw std::runtime_error("SQLite failure");
        }
        CLOG(INFO, "Ledger") << "Bulk-upserted " << jsonArrayPtrs.size()
                             << " offers";
    }

    soci::session& session = DB.getSession();
    auto sqlite =
        dynamic_cast<soci::sqlite3_session_backend*>(session.get_backend());
    if (sqlite3_changes(sqlite->conn_) != jsonArrayPtrs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sqliteSpecificBulkUpsertOffersUsingJoin(
    Database& DB, std::vector<std::string> const& sellerIDs,
    std::vector<int64_t> const& offerIDs,
    std::vector<int32_t> const& sellingAssetTypes,
    std::vector<std::string> const& sellingAssetCodes,
    std::vector<std::string> const& sellingIssuers,
    std::vector<soci::indicator>& sellingAssetCodeInds,
    std::vector<soci::indicator>& sellingIssuerInds,
    std::vector<int32_t> const& buyingAssetTypes,
    std::vector<std::string> const& buyingAssetCodes,
    std::vector<std::string> const& buyingIssuers,
    std::vector<soci::indicator>& buyingAssetCodeInds,
    std::vector<soci::indicator>& buyingIssuerInds,
    std::vector<int64_t> const& amounts, std::vector<int32_t> const& priceNs,
    std::vector<int32_t> const& priceDs, std::vector<double> const& prices,
    std::vector<int32_t> const& flags,
    std::vector<int32_t> const& lastModifieds)
{
    std::vector<const char*> cStrSellerIDs, cStrSellingAssetCodes,
        cStrSellingIssuers, cStrBuyingAssetCodes, cStrBuyingIssuers;

    marshalToSqliteArray(cStrSellerIDs, sellerIDs);
    marshalToSqliteArray(cStrSellingAssetCodes, sellingAssetCodes,
                         &sellingAssetCodeInds);
    marshalToSqliteArray(cStrSellingIssuers, sellingIssuers,
                         &sellingIssuerInds);
    marshalToSqliteArray(cStrBuyingAssetCodes, buyingAssetCodes,
                         &buyingAssetCodeInds);
    marshalToSqliteArray(cStrBuyingIssuers, buyingIssuers,
                         &buyingIssuerInds);

    std::string sqlJoin =
        "SELECT v1.value, v2.value, v3.value, v4.value, v5.value, "
        "v6.value, v7.value, v8.value, v9.value, v10.value, v11.value, "
        "v12.value, v13.value, v14.value"
        " FROM "
         "(SELECT rowid, value FROM carray(?, ?, 'char*')) AS v1 "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int64')) AS v2 ON v1.rowid = v2.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32')) AS v3 ON v1.rowid = v3.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*')) AS v4 ON v1.rowid = v4.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*')) AS v5 ON v1.rowid = v5.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32')) AS v6 ON v1.rowid = v6.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*')) AS v7 ON v1.rowid = v7.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'char*')) AS v8 ON v1.rowid = v8.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int64')) AS v9 ON v1.rowid = v9.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32')) AS v10 ON v1.rowid = v10.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32')) AS v11 ON v1.rowid = v11.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'double')) AS v12 ON v1.rowid = v12.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32')) AS v13 ON v1.rowid = v13.rowid "
         "INNER JOIN (SELECT rowid, value FROM carray(?, ?, 'int32')) AS v14 ON v1.rowid = v14.rowid ";

    std::string sql = "WITH r AS ( " + sqlJoin + ")"
                      "INSERT INTO offers ( "
                      "sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, price, flags, lastmodified "
                      ") SELECT * from r "

                      // NB: this 'WHERE true' is the official way to resolve a
                      // parsing ambiguity wrt. the following 'ON' token. Really.
                      // See: https://www.sqlite.org/lang_insert.html
                      "WHERE true "

                      "ON CONFLICT (offerid) DO UPDATE SET "
                      "sellerid = excluded.sellerid, "
                      "sellingassettype = excluded.sellingassettype, "
                      "sellingassetcode = excluded.sellingassetcode, "
                      "sellingissuer = excluded.sellingissuer, "
                      "buyingassettype = excluded.buyingassettype, "
                      "buyingassetcode = excluded.buyingassetcode, "
                      "buyingissuer = excluded.buyingissuer, "
                      "amount = excluded.amount, "
                      "pricen = excluded.pricen, "
                      "priced = excluded.priced, "
                      "price = excluded.price, "
                      "flags = excluded.flags, "
                      "lastmodified = excluded.lastmodified ";

    auto prep = DB.getPreparedStatement(sql);
    auto sqliteStatement = dynamic_cast<soci::sqlite3_statement_backend*>(prep.statement().get_backend());
    auto st = sqliteStatement->stmt_;

    sqlite3_reset(st);
    sqlite3_bind_pointer(st, 1, cStrSellerIDs.data(), "carray", 0);
    sqlite3_bind_int(st, 2, cStrSellerIDs.size());
    sqlite3_bind_pointer(st, 3, const_cast<int64_t*>(offerIDs.data()), "carray", 0);
    sqlite3_bind_int(st, 4, offerIDs.size());
    sqlite3_bind_pointer(st, 5, const_cast<int32_t*>(sellingAssetTypes.data()), "carray", 0);
    sqlite3_bind_int(st, 6, sellingAssetTypes.size());
    sqlite3_bind_pointer(st, 7, cStrSellingAssetCodes.data(), "carray", 0);
    sqlite3_bind_int(st, 8, cStrSellingAssetCodes.size());
    sqlite3_bind_pointer(st, 9, cStrSellingIssuers.data(), "carray", 0);
    sqlite3_bind_int(st, 10, cStrSellingIssuers.size());
    sqlite3_bind_pointer(st, 11, const_cast<int32_t*>(buyingAssetTypes.data()), "carray", 0);
    sqlite3_bind_int(st, 12, buyingAssetTypes.size());
    sqlite3_bind_pointer(st, 13, cStrBuyingAssetCodes.data(), "carray", 0);
    sqlite3_bind_int(st, 14, cStrBuyingAssetCodes.size());
    sqlite3_bind_pointer(st, 15, cStrBuyingIssuers.data(), "carray", 0);
    sqlite3_bind_int(st, 16, cStrBuyingIssuers.size());
    sqlite3_bind_pointer(st, 17, const_cast<int64_t*>(amounts.data()), "carray", 0);
    sqlite3_bind_int(st, 18, amounts.size());
    sqlite3_bind_pointer(st, 19, const_cast<int32_t*>(priceNs.data()), "carray", 0);
    sqlite3_bind_int(st, 20, priceNs.size());
    sqlite3_bind_pointer(st, 21, const_cast<int32_t*>(priceDs.data()), "carray", 0);
    sqlite3_bind_int(st, 22, priceDs.size());
    sqlite3_bind_pointer(st, 23, const_cast<double*>(prices.data()), "carray", 0);
    sqlite3_bind_int(st, 24, prices.size());
    sqlite3_bind_pointer(st, 25, const_cast<int32_t*>(flags.data()), "carray", 0);
    sqlite3_bind_int(st, 26, flags.size());
    sqlite3_bind_pointer(st, 27, const_cast<int32_t*>(lastModifieds.data()), "carray", 0);
    sqlite3_bind_int(st, 28, lastModifieds.size());

    {
        auto timer = DB.getUpsertTimer("offer");
        CLOG(INFO, "Ledger") << "Bulk-upsert'ing " << cStrSellerIDs.size()
                             << " offers";
        if (sqlite3_step(st) != SQLITE_DONE)
        {
            throw std::runtime_error("SQLite failure");
        }
        CLOG(INFO, "Ledger") << "Bulk-upserted " << cStrSellerIDs.size()
                             << " offers";
    }

    soci::session& session = DB.getSession();
    auto sqlite =
        dynamic_cast<soci::sqlite3_session_backend*>(session.get_backend());
    if (sqlite3_changes(sqlite->conn_) != offerIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sociGenericBulkUpsertOffers(Database& DB,
                            std::vector<std::string> const& sellerIDs,
                            std::vector<int64_t> const& offerIDs,
                            std::vector<int32_t> const& sellingAssetTypes,
                            std::vector<std::string> const& sellingAssetCodes,
                            std::vector<std::string> const& sellingIssuers,
                            std::vector<soci::indicator>& sellingAssetCodeInds,
                            std::vector<soci::indicator>& sellingIssuerInds,
                            std::vector<int32_t> const& buyingAssetTypes,
                            std::vector<std::string> const& buyingAssetCodes,
                            std::vector<std::string> const& buyingIssuers,
                            std::vector<soci::indicator>& buyingAssetCodeInds,
                            std::vector<soci::indicator>& buyingIssuerInds,
                            std::vector<int64_t> const& amounts,
                            std::vector<int32_t> const& priceNs,
                            std::vector<int32_t> const& priceDs,
                            std::vector<double> const& prices,
                            std::vector<int32_t> const& flags,
                            std::vector<int32_t> const& lastModifieds)
{
    std::string sql = "INSERT INTO offers ( "
                      "sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, price, flags, lastmodified "
                      ") VALUES ( "
                      ":sellerid, :offerid, :v1, :v2, :v3, :v4, :v5, :v6, "
                      ":v7, :v8, :v9, :v10, :v11, :v12 "
                      ") ON CONFLICT (offerid) DO UPDATE SET "
                      "sellerid = excluded.sellerid, "
                      "sellingassettype = excluded.sellingassettype, "
                      "sellingassetcode = excluded.sellingassetcode, "
                      "sellingissuer = excluded.sellingissuer, "
                      "buyingassettype = excluded.buyingassettype, "
                      "buyingassetcode = excluded.buyingassetcode, "
                      "buyingissuer = excluded.buyingissuer, "
                      "amount = excluded.amount, "
                      "pricen = excluded.pricen, "
                      "priced = excluded.priced, "
                      "price = excluded.price, "
                      "flags = excluded.flags, "
                      "lastmodified = excluded.lastmodified ";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(sellerIDs, "sellerid"));
    st.exchange(soci::use(offerIDs, "offerid"));
    st.exchange(soci::use(sellingAssetTypes, "v1"));
    st.exchange(soci::use(sellingAssetCodes, sellingAssetCodeInds, "v2"));
    st.exchange(soci::use(sellingIssuers, sellingIssuerInds, "v3"));
    st.exchange(soci::use(buyingAssetTypes, "v4"));
    st.exchange(soci::use(buyingAssetCodes, buyingAssetCodeInds, "v5"));
    st.exchange(soci::use(buyingIssuers, buyingIssuerInds, "v6"));
    st.exchange(soci::use(amounts, "v7"));
    st.exchange(soci::use(priceNs, "v8"));
    st.exchange(soci::use(priceDs, "v9"));
    st.exchange(soci::use(prices, "v10"));
    st.exchange(soci::use(flags, "v11"));
    st.exchange(soci::use(lastModifieds, "v12"));
    st.define_and_bind();
    {
        auto timer = DB.getUpsertTimer("offer");
        st.execute(true);
    }
    if (st.get_affected_rows() != offerIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
sociGenericBulkDeleteOffers(Database& DB, LedgerTxnConsistency cons,
                            std::vector<int64_t> const& offerIDs)
{
    std::string sql = "DELETE FROM offers WHERE offerid = :id";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(offerIDs, "id"));
    st.define_and_bind();
    {
        auto timer = DB.getDeleteTimer("offer");
        st.execute(true);
    }
    if (st.get_affected_rows() != offerIDs.size() &&
        cons == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

#ifdef USE_POSTGRES
static void
postgresSpecificBulkUpsertOffers(
    Database& DB, std::vector<std::string> const& sellerIDs,
    std::vector<int64_t> const& offerIDs,
    std::vector<int32_t> const& sellingAssetTypes,
    std::vector<std::string> const& sellingAssetCodes,
    std::vector<std::string> const& sellingIssuers,
    std::vector<soci::indicator>& sellingAssetCodeInds,
    std::vector<soci::indicator>& sellingIssuerInds,
    std::vector<int32_t> const& buyingAssetTypes,
    std::vector<std::string> const& buyingAssetCodes,
    std::vector<std::string> const& buyingIssuers,
    std::vector<soci::indicator>& buyingAssetCodeInds,
    std::vector<soci::indicator>& buyingIssuerInds,
    std::vector<int64_t> const& amounts, std::vector<int32_t> const& priceNs,
    std::vector<int32_t> const& priceDs, std::vector<double> const& prices,
    std::vector<int32_t> const& flags,
    std::vector<int32_t> const& lastModifieds)
{
    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;

    std::string strSellerIDs, strOfferIDs, strSellingAssetTypes,
        strSellingAssetCodes, strSellingIssuers, strBuyingAssetTypes,
        strBuyingAssetCodes, strBuyingIssuers, strAmounts, strPriceNs,
        strPriceDs, strPrices, strFlags, strLastModifieds;

    marshalToPGArray(conn, strSellerIDs, sellerIDs);
    marshalToPGArray(conn, strOfferIDs, offerIDs);

    marshalToPGArray(conn, strSellingAssetTypes, sellingAssetTypes);
    marshalToPGArray(conn, strSellingAssetCodes, sellingAssetCodes,
                     &sellingAssetCodeInds);
    marshalToPGArray(conn, strSellingIssuers, sellingIssuers,
                     &sellingIssuerInds);

    marshalToPGArray(conn, strBuyingAssetTypes, buyingAssetTypes);
    marshalToPGArray(conn, strBuyingAssetCodes, buyingAssetCodes,
                     &buyingAssetCodeInds);
    marshalToPGArray(conn, strBuyingIssuers, buyingIssuers, &buyingIssuerInds);

    marshalToPGArray(conn, strAmounts, amounts);
    marshalToPGArray(conn, strPriceNs, priceNs);
    marshalToPGArray(conn, strPriceDs, priceDs);
    marshalToPGArray(conn, strPrices, prices);
    marshalToPGArray(conn, strFlags, flags);
    marshalToPGArray(conn, strLastModifieds, lastModifieds);

    std::string sql = "WITH r AS (SELECT "
                      "unnest(:sellerids::TEXT[]), "
                      "unnest(:offerids::BIGINT[]), "
                      "unnest(:sellingassettypes::INT[]), "
                      "unnest(:sellingassetcodes::TEXT[]), "
                      "unnest(:sellingissuers::TEXT[]), "
                      "unnest(:buyingassettypes::INT[]), "
                      "unnest(:buyingassetcodes::TEXT[]), "
                      "unnest(:buyingissuers::TEXT[]), "
                      "unnest(:amounts::BIGINT[]), "
                      "unnest(:pricens::INT[]), "
                      "unnest(:priceds::INT[]), "
                      "unnest(:prices::DOUBLE PRECISION[]), "
                      "unnest(:flags::INT[]), "
                      "unnest(:lastmodifieds::INT[]) "
                      ")"
                      "INSERT INTO offers ( "
                      "sellerid, offerid, "
                      "sellingassettype, sellingassetcode, sellingissuer, "
                      "buyingassettype, buyingassetcode, buyingissuer, "
                      "amount, pricen, priced, price, flags, lastmodified "
                      ") SELECT * from r "
                      "ON CONFLICT (offerid) DO UPDATE SET "
                      "sellerid = excluded.sellerid, "
                      "sellingassettype = excluded.sellingassettype, "
                      "sellingassetcode = excluded.sellingassetcode, "
                      "sellingissuer = excluded.sellingissuer, "
                      "buyingassettype = excluded.buyingassettype, "
                      "buyingassetcode = excluded.buyingassetcode, "
                      "buyingissuer = excluded.buyingissuer, "
                      "amount = excluded.amount, "
                      "pricen = excluded.pricen, "
                      "priced = excluded.priced, "
                      "price = excluded.price, "
                      "flags = excluded.flags, "
                      "lastmodified = excluded.lastmodified ";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strSellerIDs, "sellerids"));
    st.exchange(soci::use(strOfferIDs, "offerids"));
    st.exchange(soci::use(strSellingAssetTypes, "sellingassettypes"));
    st.exchange(soci::use(strSellingAssetCodes, "sellingassetcodes"));
    st.exchange(soci::use(strSellingIssuers, "sellingissuers"));
    st.exchange(soci::use(strBuyingAssetTypes, "buyingassettypes"));
    st.exchange(soci::use(strBuyingAssetCodes, "buyingassetcodes"));
    st.exchange(soci::use(strBuyingIssuers, "buyingissuers"));
    st.exchange(soci::use(strAmounts, "amounts"));
    st.exchange(soci::use(strPriceNs, "pricens"));
    st.exchange(soci::use(strPriceDs, "priceds"));
    st.exchange(soci::use(strPrices, "prices"));
    st.exchange(soci::use(strFlags, "flags"));
    st.exchange(soci::use(strLastModifieds, "lastmodifieds"));
    st.define_and_bind();
    {
        auto timer = DB.getUpsertTimer("offer");
        st.execute(true);
    }
    if (st.get_affected_rows() != offerIDs.size())
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

static void
postgresSpecificBulkDeleteOffers(Database& DB, LedgerTxnConsistency cons,
                                 std::vector<int64_t> const& offerIDs)
{
    soci::session& session = DB.getSession();
    auto pg =
        dynamic_cast<soci::postgresql_session_backend*>(session.get_backend());
    PGconn* conn = pg->conn_;
    std::string strOfferIDs;
    marshalToPGArray(conn, strOfferIDs, offerIDs);
    std::string sql = "WITH r AS (SELECT "
                      "unnest(:ids::BIGINT[]) "
                      ") "
                      "DELETE FROM offers WHERE "
                      "(offerid) IN (SELECT * FROM r)";
    auto prep = DB.getPreparedStatement(sql);
    soci::statement& st = prep.statement();
    st.exchange(soci::use(strOfferIDs, "ids"));
    st.define_and_bind();
    {
        auto timer = DB.getDeleteTimer("offer");
        st.execute(true);
    }
    if (st.get_affected_rows() != offerIDs.size() &&
        cons == LedgerTxnConsistency::EXACT)
    {
        throw std::runtime_error("Could not update data in SQL");
    }
}

#endif

void
LedgerTxnRoot::Impl::bulkUpsertOffers(std::vector<EntryIterator> const& entries)
{
    if (mDatabase.isSqlite())
    {
        sqliteSpecificBulkUpsertOffersUsingJson(mDatabase, entries);
        return;
    }
    std::vector<std::string> sellerIDs;
    std::vector<int64_t> offerIDs;
    std::vector<int32_t> sellingAssetTypes;
    std::vector<std::string> sellingAssetCodes;
    std::vector<std::string> sellingIssuers;
    std::vector<soci::indicator> sellingAssetCodeInds;
    std::vector<soci::indicator> sellingIssuerInds;
    std::vector<int32_t> buyingAssetTypes;
    std::vector<std::string> buyingAssetCodes;
    std::vector<std::string> buyingIssuers;
    std::vector<soci::indicator> buyingAssetCodeInds;
    std::vector<soci::indicator> buyingIssuerInds;
    std::vector<int64_t> amounts;
    std::vector<int32_t> priceNs;
    std::vector<int32_t> priceDs;
    std::vector<double> prices;
    std::vector<int32_t> flags;
    std::vector<int32_t> lastModifieds;

    sellerIDs.reserve(entries.size());
    offerIDs.reserve(entries.size());
    sellingAssetTypes.reserve(entries.size());
    sellingAssetCodes.reserve(entries.size());
    sellingIssuers.reserve(entries.size());
    buyingAssetTypes.reserve(entries.size());
    buyingAssetCodes.reserve(entries.size());
    buyingIssuers.reserve(entries.size());
    amounts.reserve(entries.size());
    priceNs.reserve(entries.size());
    priceDs.reserve(entries.size());
    prices.reserve(entries.size());
    flags.reserve(entries.size());
    lastModifieds.reserve(entries.size());

    for (auto const& e : entries)
    {
        assert(e.entryExists());
        assert(e.entry().data.type() == OFFER);
        auto const& offer = e.entry().data.offer();
        std::string sellerIDStr, sellingIssuerStr, sellingAssetCodeStr,
            buyingIssuerStr, buyingAssetCodeStr;
        soci::indicator sellingIssuerInd, sellingAssetCodeInd, buyingIssuerInd,
            buyingAssetCodeInd;
        getAssetStrings(offer.selling, sellingAssetCodeStr, sellingIssuerStr,
                        sellingAssetCodeInd, sellingIssuerInd);
        getAssetStrings(offer.buying, buyingAssetCodeStr, buyingIssuerStr,
                        buyingAssetCodeInd, buyingIssuerInd);

        sellerIDStr = KeyUtils::toStrKey(offer.sellerID);
        sellerIDs.push_back(sellerIDStr);
        offerIDs.push_back(offer.offerID);

        sellingAssetTypes.push_back(
            unsignedToSigned(static_cast<uint32_t>(offer.selling.type())));
        sellingAssetCodes.push_back(sellingAssetCodeStr);
        sellingIssuers.push_back(sellingIssuerStr);
        sellingAssetCodeInds.push_back(sellingAssetCodeInd);
        sellingIssuerInds.push_back(sellingIssuerInd);

        buyingAssetTypes.push_back(
            unsignedToSigned(static_cast<uint32_t>(offer.buying.type())));
        buyingAssetCodes.push_back(buyingAssetCodeStr);
        buyingIssuers.push_back(buyingIssuerStr);
        buyingAssetCodeInds.push_back(buyingAssetCodeInd);
        buyingIssuerInds.push_back(buyingIssuerInd);

        amounts.push_back(offer.amount);
        priceNs.push_back(offer.price.n);
        priceDs.push_back(offer.price.d);
        double price = double(offer.price.n) / double(offer.price.d);
        prices.push_back(price);

        flags.push_back(unsignedToSigned(offer.flags));
        lastModifieds.push_back(
            unsignedToSigned(e.entry().lastModifiedLedgerSeq));

        dropFromEntryCacheIfPresent(e.key());
    }

    // At the moment we only have two flavors of database support, this
    // condition 2-way split will need to change if we support more.
    if (mDatabase.isSqlite())
    {
        /*sociGenericBulkUpsertOffers*/
        /*sqliteSpecificBulkUpsertOffersUsingJoin(
            mDatabase, sellerIDs, offerIDs, sellingAssetTypes,
            sellingAssetCodes, sellingIssuers, sellingAssetCodeInds,
            sellingIssuerInds, buyingAssetTypes, buyingAssetCodes,
            buyingIssuers, buyingAssetCodeInds, buyingIssuerInds, amounts,
            priceNs, priceDs, prices, flags, lastModifieds);
        */
        sqliteSpecificBulkUpsertOffersUsingJson(mDatabase, entries);

    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkUpsertOffers(
            mDatabase, sellerIDs, offerIDs, sellingAssetTypes,
            sellingAssetCodes, sellingIssuers, sellingAssetCodeInds,
            sellingIssuerInds, buyingAssetTypes, buyingAssetCodes,
            buyingIssuers, buyingAssetCodeInds, buyingIssuerInds, amounts,
            priceNs, priceDs, prices, flags, lastModifieds);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::bulkDeleteOffers(std::vector<EntryIterator> const& entries)
{
    std::vector<int64_t> offerIDs;
    for (auto const& e : entries)
    {
        assert(!e.entryExists());
        assert(e.key().type() == OFFER);
        auto const& offer = e.key().offer();
        offerIDs.push_back(offer.offerID);
        dropFromEntryCacheIfPresent(e.key());
    }
    // At the moment we only have two flavors of database support, this
    // condition 2-way split will need to change if we support more.
    if (mDatabase.isSqlite())
    {
        sociGenericBulkDeleteOffers(mDatabase, mConsistency, offerIDs);
    }
    else
    {
#ifdef USE_POSTGRES
        postgresSpecificBulkDeleteOffers(mDatabase, mConsistency, offerIDs);
#else
        throw std::runtime_error("Not compiled with postgres support");
#endif
    }
}

void
LedgerTxnRoot::Impl::dropOffers()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffersCache.clear();

    mDatabase.getSession() << "DROP TABLE IF EXISTS offers;";
    mDatabase.getSession()
        << "CREATE TABLE offers"
           "("
           "sellerid         VARCHAR(56)  NOT NULL,"
           "offerid          BIGINT       NOT NULL CHECK (offerid >= 0),"
           "sellingassettype INT          NOT NULL,"
           "sellingassetcode VARCHAR(12),"
           "sellingissuer    VARCHAR(56),"
           "buyingassettype  INT          NOT NULL,"
           "buyingassetcode  VARCHAR(12),"
           "buyingissuer     VARCHAR(56),"
           "amount           BIGINT           NOT NULL CHECK (amount >= 0),"
           "pricen           INT              NOT NULL,"
           "priced           INT              NOT NULL,"
           "price            DOUBLE PRECISION NOT NULL,"
           "flags            INT              NOT NULL,"
           "lastmodified     INT              NOT NULL,"
           "PRIMARY KEY      (offerid)"
           ");";
    mDatabase.getSession()
        << "CREATE INDEX sellingissuerindex ON offers (sellingissuer);";
    mDatabase.getSession()
        << "CREATE INDEX buyingissuerindex ON offers (buyingissuer);";
    mDatabase.getSession() << "CREATE INDEX priceindex ON offers (price);";
}
}
