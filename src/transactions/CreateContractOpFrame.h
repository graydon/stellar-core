#pragma once
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/OperationFrame.h"

namespace stellar
{

class AbstractLedgerTxn;

class CreateContractOpFrame : public OperationFrame
{
    CreateContractResult&
    innerResult()
    {
        return mResult.tr().createContractResult();
    }

    CreateContractOp const& mCreateContract;

  public:
    CreateContractOpFrame(Operation const& op, OperationResult& res,
                          TransactionFrame& parentTx);

    bool isOpSupported(LedgerHeader const& header) const override;

    bool doApply(AbstractLedgerTxn& ltx) override;
    bool doCheckValid(uint32_t ledgerVersion) override;

    static CreateContractResultCode
    getInnerCode(OperationResult const& res)
    {
        return res.tr().createContractResult().code();
    }
};
}
#endif