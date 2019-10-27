// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerCloseMetaStream.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

LedgerCloseMetaStream::LedgerCloseMetaStream(asio::io_context &ctx, int fd) :
    mOutputStream(ctx)
{
    CLOG(INFO, "Ledger")
        << "Streaming metadata changes to file descriptor " << fd;
    mOutputStream.next_layer().assign(fd);
}

void
LedgerCloseMetaStream::writeHandler(asio::error_code const& error,
                                    std::size_t bytes_transferred)
{
    stellar::assertThreadIsMain();
    if (error)
    {
        throw std::runtime_error(std::string("error writing stream: ") +
                                 error.message());
    }
}


void
LedgerCloseMetaStream::messageSender()
{
    stellar::assertThreadIsMain();
    auto self = std::static_pointer_cast<LedgerCloseMetaStream>(shared_from_this());
    // if nothing to do, flush and return
    if (mWriteQueue.empty())
    {
        mOutputStream.async_flush([self](asio::error_code const& ec, std::size_t) {
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
LedgerCloseMetaStream::writeMetaToStream(stellar::LedgerCloseMeta const& lcm)
{
    stellar::assertThreadIsMain();
    xdr::msg_ptr xdrBytes(xdr::xdr_to_msg(lcm));
    auto buf = std::make_shared<xdr::msg_ptr>(std::move(xdrBytes));
    mWriteQueue.emplace(std::move(buf));
    if (!mWriting)
    {
        mWriting = true;
        messageSender();
    }
}

bool
LedgerCloseMetaStream::isStreaming() const
{
    return mWriting || !mWriteQueue.empty();
}
