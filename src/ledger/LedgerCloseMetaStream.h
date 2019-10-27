#pragma once

// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/asio.h"
#include "util/LocalStream.h"
#include "util/NonCopyable.h"
#include "xdr/Stellar-ledger.h"
#include "xdrpp/message.h"
#include <memory>
#include <queue>

// This class is responsible for writing an XDR stream representing ledger-close
// metadata (txmeta, transaction-result pair and so forth) to a local file
// descriptor. This only works on POSIX for the time being.
//
// Writes are asynchronous (via ASIO) and buffered in memory. This risks
// using up too much memory if a consumer can't keep up. A config option
// METADATA_BUFFER_LIMIT can be set (it defaults to 100MB) and clients
// can poll the `bufferLimitExceeded()` method to see if the limit is
// currently exceeded.
//
// How to handle limit-exceeding is left to clients; in replay mode the
// catchup-work should probably just pause/retry until there's room; in live
// mode we might want to throw an exception / crash, since the other option
// (gradually running out of memory on the machine) is potentially worse.
namespace stellar
{

class LedgerCloseMetaStream
    : public std::enable_shared_from_this<LedgerCloseMetaStream>,
      public stellar::NonMovableOrCopyable
{
  private:
    size_t const mBufferLimitBytes;
    size_t mBufferedBytes;
    std::queue<std::shared_ptr<xdr::msg_ptr>> mWriteQueue;
    bool mWriting{false};
    asio::buffered_write_stream<localstream::StreamType> mOutputStream;
    void messageSender();
    void writeHandler(asio::error_code const& error,
                      std::size_t bytes_transferred);

  public:
    LedgerCloseMetaStream(asio::io_context& ctx, localstream::HandleType handle,
                          size_t bufferLimitBytes);
    ~LedgerCloseMetaStream();
    void writeMetaToStream(LedgerCloseMeta const& lcm);
    bool isStreaming() const;
    bool bufferLimitExceeded() const;
};
}
