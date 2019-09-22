#pragma once

// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ByteSlice.h"
#include <lib/util/siphash.h>
#include <xdrpp/endian.h>
#include <xdrpp/marshal.h>

namespace stellar
{

// shortHash provides a fast and relatively secure *randomized* hash function
// this is suitable for keeping objects in memory but not for persisting objects
// or cryptographic use
namespace shortHash
{
void initialize();
uint64_t computeHash(stellar::ByteSlice const& b);

struct XDRSipHasher
{

    SipHash h;
    XDRSipHasher();

    template <typename T>
    typename std::enable_if<std::is_same<
        std::uint32_t, typename xdr::xdr_traits<T>::uint_type>::value>::type
    operator()(T t)
    {
        auto u = xdr::swap32le(xdr::xdr_traits<T>::to_uint(t));
        h.update_le_u32(u);
    }

    template <typename T>
    typename std::enable_if<std::is_same<
        std::uint64_t, typename xdr::xdr_traits<T>::uint_type>::value>::type
    operator()(T t)
    {
        auto u = xdr::swap64le(xdr::xdr_traits<T>::to_uint(t));
        h.update_le_u64(u);
    }

    template <typename T>
    typename std::enable_if<xdr::xdr_traits<T>::is_bytes>::type
    operator()(const T& t)
    {
        if (xdr::xdr_traits<T>::variable_nelem)
        {
            (*this)(static_cast<uint32_t>(t.size()));
        }
        size_t len = t.size();
        h.update(reinterpret_cast<const unsigned char*>(t.data()), len);
        // Pad to 4-byte boundary.
        while (len & 3)
        {
            ++len;
            h.update_u8('\0');
        }
    }

    template <typename T>
    typename std::enable_if<xdr::xdr_traits<T>::is_class ||
                            xdr::xdr_traits<T>::is_container>::type
    operator()(const T& t)
    {
        xdr::xdr_traits<T>::save(*this, t);
    }
};

// Equivalent to `computeHash(xdr_to_opaque(t))` on any XDR object `t` but
// without allocating a temporary buffer. Runs the same (SipHash2,4) short-hash
// function, randomized with the same per-process key as `computeHash`. Uses
// a different implementation, but results are (unit-tested to be) identical.
//
// NB: This is not an overload of `computeHash` to avoid ambiguity when called
// with xdrpp-provided types like opaque_vec, which will convert to a ByteSlice
// if demanded, but can also be passed to XDRSipHasher. Depending on which it
// goes to, it'll hash differently: length+body (XDR case) or just body
// (ByteSlice case). This difference isn't a security feature or anything
// (SipHash integrates length into the hash) but it's a source of potential
// bugs, so we avoid it by using a different function name.
template <typename T>
uint64_t
computeXDRHash(T& t)
{
    XDRSipHasher xsh;
    xdr::archive(xsh, t);
    return xsh.h.digest();
}
}
}
