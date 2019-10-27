// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerCloseMetaStream.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

namespace stellar
{

LedgerCloseMetaStream::LedgerCloseMetaStream(asio::io_context& ctx,
                                             localstream::HandleType handle,
                                             size_t bufferLimitBytes)
    : mBufferLimitBytes(bufferLimitBytes), mBufferedBytes(0), mOutputStream(ctx)
{
    CLOG(INFO, "Ledger") << "Streaming metadata changes to local stream handle";
    mOutputStream.next_layer().assign(handle);
}

LedgerCloseMetaStream::~LedgerCloseMetaStream()
{
    localstream::closeHandle(mOutputStream.next_layer().native_handle());
}

void
LedgerCloseMetaStream::writeHandler(asio::error_code const& error,
                                    std::size_t bytes_transferred)
{
    assertThreadIsMain();
    if (mBufferedBytes < bytes_transferred)
    {
        CLOG(WARNING, "Ledger") << "Metadata stream buffer-size underflow";
        mBufferedBytes = bytes_transferred;
    }
    mBufferedBytes -= bytes_transferred;
    if (error)
    {
        throw std::runtime_error(std::string("error writing stream: ") +
                                 error.message());
    }
}

void
LedgerCloseMetaStream::messageSender()
{
    assertThreadIsMain();
    auto self =
        std::static_pointer_cast<LedgerCloseMetaStream>(shared_from_this());
    // if nothing to do, flush and return
    if (mWriteQueue.empty())
    {
        mOutputStream.async_flush(
            [self](asio::error_code const& ec, std::size_t) {
                self->writeHandler(ec, 0);
                if (!ec)
                {
                    if (!self->mWriteQueue.empty())
                    {
                        self->messageSender();
                    }
                    else
                    {
                        self->mWriting = false;
                    }
                }
            });
        return;
    }

    // peek the buffer from the queue
    // do not remove it yet as we need the buffer for the duration of the
    // write operation
    auto buf = mWriteQueue.front();
    asio::async_write(mOutputStream,
                      asio::buffer((*buf)->raw_data(), (*buf)->raw_size()),
                      [self](asio::error_code const& ec, std::size_t length) {
                          self->writeHandler(ec, length);
                          self->mWriteQueue.pop(); // done with front element
                          // continue processing the queue/flush
                          if (!ec)
                          {
                              self->messageSender();
                          }
                      });
}

void
LedgerCloseMetaStream::writeMetaToStream(LedgerCloseMeta const& lcm)
{
    assertThreadIsMain();
    xdr::msg_ptr xdrBytes(xdr::xdr_to_msg(lcm));
    mBufferedBytes += xdrBytes->raw_size();
    auto buf = std::make_shared<xdr::msg_ptr>(std::move(xdrBytes));
    mWriteQueue.emplace(std::move(buf));
    if (!mWriting)
    {
        mWriting = true;
        messageSender();
    }
    if (bufferLimitExceeded())
    {
        CLOG(WARNING, "Ledger") << "Metadata stream buffer is overfull at "
                                << mBufferedBytes << " bytes";
    }
}

bool
LedgerCloseMetaStream::bufferEmpty() const
{
    return !mWriting && mWriteQueue.empty();
}

bool
LedgerCloseMetaStream::bufferLimitExceeded() const
{
    return mBufferedBytes > mBufferLimitBytes;
}
}
