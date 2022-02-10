#include "herder/TxSetFrame.h"
#include <xdr/Stellar-transaction.h>

namespace stellar
{
void partitionTxSetForConcurrency(TransactionSet const& txset);
}