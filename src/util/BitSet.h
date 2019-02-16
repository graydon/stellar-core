#pragma once

// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// C++ value-semantic / convenience wrapper around C bitset_t

#include <memory>
#include <ostream>
#include <set>

extern "C" {
#include "cbitset.h"
};

class BitSet
{
    std::unique_ptr<bitset_t, decltype(&bitset_free)> mPtr;

  public:
    BitSet() : mPtr(bitset_create(), &bitset_free)
    {
    }
    BitSet(size_t n) : mPtr(bitset_create_with_capacity(n), &bitset_free)
    {
    }
    BitSet(std::set<size_t> const& s)
        : mPtr(bitset_create_with_capacity(s.empty() ? 0 : *s.end()),
               &bitset_free)
    {
        for (auto i : s)
            set(i);
    }
    BitSet(BitSet const& other)
        : mPtr(bitset_copy(other.mPtr.get()), &bitset_free)
    {
    }
    BitSet&
    operator=(BitSet const& other)
    {
        mPtr = decltype(mPtr)(bitset_copy(other.mPtr.get()), &bitset_free);
        return *this;
    }
    BitSet(BitSet&& other) = default;
    BitSet& operator=(BitSet&& other) = default;

    bool
    operator==(BitSet const& other) const
    {
        return bitset_equal(mPtr.get(), other.mPtr.get());
    }

    bool
    is_subseteq(BitSet const& other) const
    {
        return bitset_subseteq(mPtr.get(), other.mPtr.get());
    }

    bool
    operator<=(BitSet const& other) const
    {
        return is_subseteq(other);
    }

    size_t
    size() const
    {
        return bitset_size_in_bits(mPtr.get());
    }
    void
    set(size_t i)
    {
        bitset_set(mPtr.get(), i);
    }
    bool
    get(size_t i) const
    {
        return bitset_get(mPtr.get(), i);
    }
    void
    clear()
    {
        return bitset_clear(mPtr.get());
    }

    size_t
    count() const
    {
        return bitset_count(mPtr.get());
    }
    size_t
    min() const
    {
        return bitset_minimum(mPtr.get());
    }
    size_t
    max() const
    {
        return bitset_maximum(mPtr.get());
    }

    void
    inplace_union(BitSet const& other)
    {
        bitset_inplace_union(mPtr.get(), other.mPtr.get());
    }
    BitSet
    operator|(BitSet const& other) const
    {
        BitSet tmp(*this);
        tmp.inplace_union(other);
        return tmp;
    }
    void
    operator|=(BitSet const& other)
    {
        inplace_union(other);
    }

    void
    inplace_intersection(BitSet const& other)
    {
        bitset_inplace_intersection(mPtr.get(), other.mPtr.get());
    }
    BitSet operator&(BitSet const& other) const
    {
        BitSet tmp(*this);
        tmp.inplace_intersection(other);
        return tmp;
    }
    void
    operator&=(BitSet const& other)
    {
        inplace_intersection(other);
    }

    void
    inplace_difference(BitSet const& other)
    {
        bitset_inplace_difference(mPtr.get(), other.mPtr.get());
    }
    BitSet
    operator-(BitSet const& other) const
    {
        BitSet tmp(*this);
        tmp.inplace_difference(other);
        return tmp;
    }
    void
    operator-=(BitSet const& other)
    {
        inplace_difference(other);
    }

    void
    inplace_symmetric_difference(BitSet const& other)
    {
        bitset_inplace_symmetric_difference(mPtr.get(), other.mPtr.get());
    }
    BitSet
    symmetric_difference(BitSet const& other)
    {
        BitSet tmp(*this);
        tmp.inplace_symmetric_difference(other);
        return tmp;
    }

    size_t
    union_count(BitSet const& other)
    {
        return bitset_union_count(mPtr.get(), other.mPtr.get());
    }
    size_t
    intersection_count(BitSet const& other)
    {
        return bitset_intersection_count(mPtr.get(), other.mPtr.get());
    }
    size_t
    difference_count(BitSet const& other)
    {
        return bitset_difference_count(mPtr.get(), other.mPtr.get());
    }
    size_t
    symmetric_difference_count(BitSet const& other)
    {
        return bitset_symmetric_difference_count(mPtr.get(), other.mPtr.get());
    }
    bool
    next_set(size_t& i) const
    {
        return nextSetBit(mPtr.get(), &i);
    }
    void
    print()
    {
        bitset_print(mPtr.get());
    }
};

inline std::ostream&
operator<<(std::ostream& out, BitSet const& b)
{
    out << '{';
    bool first = true;
    for (size_t i = 0; b.next_set(i); ++i)
    {
        if (first)
        {
            first = false;
        }
        else
        {
            out << ',';
        }
        out << i;
    }
    out << '}';
    return out;
}
