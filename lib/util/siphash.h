#pragma once

// Adapted from https://github.com/whitfin/siphash-cpp
// Copyright 2016 Isaac Whitfield
// Licensed under the MIT license
// http://opensource.org/licenses/MIT

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

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
    inline void
    compress()
    {
        v0 += v1;
        v1 = rotate_left(v1, 13);
        v1 ^= v0;
        v0 = rotate_left(v0, 32);
        v2 += v3;
        v3 = rotate_left(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = rotate_left(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = rotate_left(v1, 17);
        v1 ^= v2;
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
        m_idx = 0;
        m = 0;
    }

  public:
    SipHash(const unsigned char key[16], int c = 2, int d = 4);
    ~SipHash();

    void
    maybe_digest_block()
    {
        if (m_idx >= 8)
        {
            digest_block();
        }
    }
    void
    update_u8(uint8_t data)
    {
        input_len++;
        m |= (static_cast<uint64_t>(data) << (m_idx++ * 8));
        maybe_digest_block();
    }
    void
    update_le_u16(uint16_t data)
    {
        if (m_idx <= (sizeof(uint64_t) - sizeof(uint16_t)))
        {
            input_len += sizeof(uint16_t);
            m |= (static_cast<uint64_t>(data) << (m_idx * 8));
            m_idx += sizeof(uint16_t);
            maybe_digest_block();
        }
        else
        {
            update_u8(static_cast<uint8_t>(data));
            update_u8(static_cast<uint8_t>(data >> 8));
        }
    }
    void
    update_le_u32(uint32_t data)
    {
        if (m_idx <= (sizeof(uint64_t) - sizeof(uint32_t)))
        {
            input_len += sizeof(uint32_t);
            m |= (static_cast<uint64_t>(data) << (m_idx * 8));
            m_idx += sizeof(uint32_t);
            maybe_digest_block();
        }
        else
        {
            update_le_u16(static_cast<uint16_t>(data));
            update_le_u16(static_cast<uint16_t>(data >> 16));
        }
    }
    void
    update_le_u64(uint64_t data)
    {
        if (m_idx == 0)
        {
            input_len += sizeof(uint64_t);
            m = data;
            digest_block();
        }
        else
        {
            update_le_u32(static_cast<uint32_t>(data));
            update_le_u32(static_cast<uint32_t>(data >> 32));
        }
    }
    static uint64_t
    load_le_64(uint8_t const* p)
    {
        // NB: LLVM will boil this down to a single 64bit load on an
        // LE target.
        return (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |
                ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |
                ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |
                ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56));
    }
    static uint32_t
    load_le_32(uint8_t const* p)
    {
        return (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) |
                ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24));
    }
    static uint32_t
    load_le_16(uint8_t const* p)
    {
        return (((uint16_t)((p)[0])) | ((uint16_t)((p)[1]) << 8));
    }
    void
    update(const unsigned char* data, size_t len)
    {
        while (len != 0)
        {
            size_t n = std::min(len, static_cast<size_t>(8 - m_idx));
            switch (n)
            {
            case sizeof(uint64_t):
                update_le_u64(load_le_64(data));
                data += n;
                len -= n;
                break;
            case sizeof(uint32_t):
                update_le_u32(load_le_32(data));
                data += n;
                len -= n;
                break;
            case sizeof(uint16_t):
                update_le_u16(load_le_16(data));
                data += n;
                len -= n;
                break;
            default:
                update_u8(*data);
                ++data;
                --len;
                break;
            }
        }
    }
    uint64_t digest();
};
