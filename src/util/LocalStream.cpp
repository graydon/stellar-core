// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/LocalStream.h"
#ifdef _WIN32
#include <io.h>
#endif

namespace stellar
{
namespace localstream
{

HandleType
openWriteHandleFromPathname(std::string const& pathName)
{
    static const std::string err("Failed to open local stream from path: ");
#ifdef _WIN32
    HANDLE handle = ::CreateFile(pathName.c_str(), GENERIC_WRITE,
                                 0,                    // No sharing
                                 NULL,                 // Default security attributes
                                 OPEN_EXISTING,        // Existing pipe
                                 FILE_FLAG_OVERLAPPED, // Allow ASIO/IOCP
                                 NULL);                // No template file
    if (handle == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error(err + pathName);
    }
    return handle;
#else
    int fd = ::open(pathName.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd == -1)
    {
        throw std::runtime_error(err + pathName);
    }
    return fd;
#endif
}

HandleType
openWriteHandleFromFileDescriptor(int fd)
{
#ifdef _WIN32
    // This is very unlikely to ever work on windows (you need to
    // convince the C Runtime Library to start up with a file descriptor
    // connected to some HANDLE of interest) but it's harmless to try.
    //
    // NB: ASIO will _not_ work with WIN32 anonymous pipes, so don't
    // try that!
    intptr_t res = _get_osfhandle(fd);
    if (res == -1)
    {
        throw std::runtime_error("Failed to open file descriptor");
    }
    return (HANDLE)res;
#else
    // On POSIX, HandleType _is_ int; fd is already a HandleType.
    // Just check that it's actually open and writable.
    int flags = ::fcntl(fd, F_GETFD);
    if (flags == -1)
    {
        throw std::runtime_error("Unknown file descriptor");
    }
    // While we're here, also set O_CLOEXEC so that subprocesses we run don't
    // accidentally interfere with this stream.
    if (::fcntl(fd, F_SETFD, flags | O_CLOEXEC) == -1)
    {
        throw std::runtime_error("Failed to set fd close-on-exec flag");
    }
    return fd;
#endif
}

void
closeHandle(HandleType handle)
{
    static const std::string err("Failed to close local stream handle");
#ifdef _WIN32
    if (::CloseHandle(handle) != 0)
    {
        throw std::runtime_error(err);
    }
#else
    if (::close(handle) != 0)
    {
        throw std::runtime_error(err);
    }
#endif
}
}
}
