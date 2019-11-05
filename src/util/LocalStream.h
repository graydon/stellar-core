#pragma once

// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// This file provides platform-agnostic typedefs and helper functions
// for a "local stream" meaning one of either:
//
//  - an inherited / anonymous file descriptor on POSIX
//  - a filesystem-level fifo opened by name on POSIX
//  - a named pipe (`\\.\pipe\foo`) on WIN32
//
// These are used for streaming metadata to clients, and possibly other
// future uses.

#include "util/asio.h"

namespace stellar
{
namespace localstream
{

#ifdef _WIN32
// Windows: StreamType::native_handle_type is 'HANDLE'
using StreamType = asio::windows::stream_handle;
#else
// POSIX: StreamType::native_handle_type is 'int'
using StreamType = asio::posix::stream_descriptor;
#endif

using HandleType = StreamType::native_handle_type;

// Attempts to convert the name of a fifo or named pipe to a stream handle,
// failing if it can't be opened in write mode.
HandleType openWriteHandleFromPathname(std::string const& pathName);

// Attempts to convert a file descriptor to a stream handle, failing if it's not
// available (eg. on windows).
HandleType openWriteHandleFromFileDescriptor(int fd);

void closeHandle(HandleType);
}
}
