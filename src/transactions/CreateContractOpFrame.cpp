// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
#include "transactions/CreateContractOpFrame.h"
#include "crypto/SHA.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "transactions/TransactionUtils.h"
#include "util/ProtocolVersion.h"
#include "xdr/Stellar-contract.h"

namespace stellar
{

CreateContractOpFrame::CreateContractOpFrame(Operation const& op,
                                             OperationResult& res,
                                             TransactionFrame& parentTx)
    : OperationFrame(op, res, parentTx)
    , mCreateContract(mOperation.body.createContractOp())
{
}

bool
CreateContractOpFrame::isOpSupported(LedgerHeader const& header) const
{
    return protocolVersionStartsFrom(header.ledgerVersion,
                                     ProtocolVersion::V_20);
}

bool
CreateContractOpFrame::doApply(AbstractLedgerTxn& ltx)
{
    HashIDPreimage hashPreimage;
    hashPreimage.type(ENVELOPE_TYPE_CONTRACT_ID);
    hashPreimage.contractID().sourceAccount = getSourceID();
    hashPreimage.contractID().salt = mCreateContract.salt;

    Hash contractID = xdrSha256(hashPreimage);

    SCVal dataKey;
    dataKey.type(SCV_STATIC);
    dataKey.ic() = SCS_LEDGER_KEY_CONTRACT_CODE_WASM;
    auto codeEntry = stellar::loadContractData(ltx, dataKey, contractID);
    if (codeEntry)
    {
        innerResult().code(CREATE_CONTRACT_ALREADY_EXISTS);
        return false;
    }

    LedgerEntry le;
    le.data.type(CONTRACT_DATA);
    auto& code = le.data.contractData();
    code.contractID = contractID;
    code.key = dataKey;
    code.val.type(SCV_OBJECT);
    code.val.obj().activate();
    code.val.obj()->type(SCO_BINARY);
    code.val.obj()->bin() = mCreateContract.body;

    ltx.create(le);

    innerResult().code(CREATE_CONTRACT_SUCCESS);
    return true;
}

bool
CreateContractOpFrame::doCheckValid(uint32_t ledgerVersion)
{
    return true;
}

}
#endif