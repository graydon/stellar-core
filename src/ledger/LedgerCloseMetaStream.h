#pragma once

// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/asio.h"
#include "util/NonCopyable.h"
#include "xdr/Stellar-ledger.h"
#include "xdrpp/message.h"
#include <queue>
#include <memory>

// This class is responsible for writing an XDR stream representing ledger-close
// metadata (txmeta, transaction-result pair and so forth) to a local file
// descriptor. This only works on POSIX for the time being.
//
// Writes are asynchronous (via ASIO) and buffered in memory, but can
// potentially overflow a limit; if such a limit is set and overflow occurs,
// buffering a subsequent write will throw.
class LedgerCloseMetaStream : public std::enable_shared_from_this<LedgerCloseMetaStream>,
                              public stellar::NonMovableOrCopyable
{
    std::queue<std::shared_ptr<xdr::msg_ptr>> mWriteQueue;
    bool mWriting{false};
    asio::buffered_write_stream<asio::posix::stream_descriptor> mOutputStream;
    void messageSender();
    void writeHandler(asio::error_code const& error,
                      std::size_t bytes_transferred);

public:
    LedgerCloseMetaStream(asio::io_context &ctx, int fd);
    void writeMetaToStream(stellar::LedgerCloseMeta const& lcm);
    bool isStreaming() const;
};
