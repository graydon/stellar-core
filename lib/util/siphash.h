#pragma once

// Adapted from https://github.com/whitfin/siphash-cpp
// Copyright 2016 Isaac Whitfield
// Licensed under the MIT license
// http://opensource.org/licenses/MIT

#include <cstddef>
#include <cstdint>

class SipHash
{
  private:
    int c, d, m_idx;
    uint64_t v0, v1, v2, v3, m;
    unsigned char input_len;
    static uint64_t
    rotate_left(uint64_t x, int b)
    {
        return ((x << b) | (x >> (64 - b)));
    }
    void
    compress()
    {
        v0 += v1;
        v2 += v3;
        v1 = rotate_left(v1, 13);
        v3 = rotate_left(v3, 16);
        v1 ^= v0;
        v3 ^= v2;
        v0 = rotate_left(v0, 32);
        v2 += v1;
        v0 += v3;
        v1 = rotate_left(v1, 17);
        v3 = rotate_left(v3, 21);
        v1 ^= v2;
        v3 ^= v0;
        v2 = rotate_left(v2, 32);
    }
    void
    digest_block()
    {
        v3 ^= m;
        for (int i = 0; i < c; i++)
        {
            compress();
        }
        v0 ^= m;
    }

  public:
    SipHash(const unsigned char key[16], int c = 2, int d = 4);
    ~SipHash();
    void
    update(const unsigned char data)
    {
        input_len++;
        m |= (((uint64_t)data & 0xff) << (m_idx++ * 8));
        if (m_idx >= 8)
        {
            digest_block();
            m_idx = 0;
            m = 0;
        }
    }
    void
    update(const unsigned char* data, size_t len)
    {
        for (const unsigned char* c = data; c != data + len; ++c)
        {
            update(*c);
        }
    }
    uint64_t digest();
};
